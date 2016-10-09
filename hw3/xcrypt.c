#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <asm/page.h>
#include "job.h"
#include "util.h"

void dalloc_xcrypt(struct job *job)
{
	struct xcrypt_config *kxc = job->xcrypt_config;

	kfree(kxc->infile);
	kfree(kxc->outfile);
	kfree(kxc->cipher);
	kfree(kxc->keybuf);
	kfree(kxc);

	kfree(job);
}

static void callback(struct job *job, int err)
{
	struct callback cb;
	cb.jobid = job->jobid;
	cb.result = err;
	cb.msglen = 0;

	callback_socket(job->pid, cb);
}

unsigned char *md5hash(unsigned char *key, int keylen)
{
	struct crypto_hash *tfm = NULL;
	struct scatterlist sg;
	struct hash_desc desc;
	unsigned char *hash = NULL;
	int err;

	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		printk("error in cypto_alloc_hash in md5hash\n");
		err = PTR_ERR(tfm);
		goto out_error;
	}

	desc.tfm = tfm;
	desc.flags = 0;
	sg_init_one(&sg, key, keylen);

	hash = kmalloc(16, GFP_KERNEL);
	if (hash == NULL) {
		printk("error while kmalloc for hash in md5hash\n");
		err = -ENOMEM;
		goto out_error;
	}

	err = crypto_hash_init(&desc);
	if (err) {
		printk("error in crypto_hash_init in md5hash\n");
		goto out_error;
	}

	err = crypto_hash_update(&desc, &sg, keylen);
	if (err) {
		printk("error in crypto_hash_update in md5hash\n");
		goto out_error;
	}

	err = crypto_hash_final(&desc, hash);
	if (err) {
		printk("error in crypto_hash_final in md5hash\n");
		goto out_error;
	}

	kfree(tfm);
	return hash;

      out_error:
	if (!IS_ERR(tfm))
		kfree(tfm);
	kfree(hash);

	return ERR_PTR(err);
}

/* prepares a 16byte iv from page_num and inode number passed to it */
unsigned char *get_iv(u64 page_num, u64 ino)
{
	unsigned char *iv = NULL;

	iv = kmalloc(16, GFP_KERNEL);
	if (iv == NULL) {
		printk("error allocating memory in get_iv\n");
		return ERR_PTR(-ENOMEM);
	}
	memcpy(iv, &page_num, 8);
	memcpy(&iv[8], &ino, 8);

	return iv;
}

/* writes the data to the output file after encrypting/decrypting depending on the flags
   reference:  http://www.chronox.de/crypto-API/ch06s02.html
*/
int write(struct file *inf, struct file *temp_outf, char *cipher,
	  unsigned char *keybuf, int keylen, int flags, char **iv)
{
	struct crypto_blkcipher *blkcipher = NULL;
	struct blkcipher_desc desc;
	struct scatterlist sg;
	int err = 0, size_read, size_written;
	char *buf = NULL;
	mm_segment_t fs = get_fs();
	char *algname = NULL;
	u64 page_num = 1;

	/* uses the cipher name passed by user and mode as 'ctr' */
	algname = kmalloc(strlen(cipher) + 6, GFP_KERNEL);
	if (algname == NULL) {
		printk("error allocating memory for algname\n");
		err = -ENOMEM;
		goto out;
	}
	memcpy(algname, "ctr(", 4);
	memcpy(&algname[4], cipher, strlen(cipher));
	memcpy(&algname[4 + strlen(cipher)], ")", 1);
	memcpy(&algname[4 + strlen(cipher) + 1], "\0", 1);

	blkcipher = crypto_alloc_blkcipher(algname, 0, 0);
	if (IS_ERR(blkcipher)) {
		printk("error in crypto_alloc_blkcipher\n");
		err = PTR_ERR(blkcipher);

		/* in case the err is -ENOENT, it means the cipher name passed by user is invalid */
		if (err == -ENOENT)
			err = -EINVAL;
		goto out;
	}
	err = crypto_blkcipher_setkey(blkcipher, keybuf, keylen);
	if (err) {
		printk("error in crypto_blkcipher_setkey\n");
		goto out;
	}
	desc.tfm = blkcipher;
	desc.flags = 0;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL) {
		printk("error while kmalloc for buf\n");
		err = -ENOMEM;
		goto out;
	}
	sg_init_one(&sg, buf, PAGE_SIZE);

	set_fs(get_ds());
	while ((size_read =
		inf->f_op->read(inf, buf, PAGE_SIZE, &inf->f_pos)) > 0) {
		crypto_blkcipher_set_iv(blkcipher, *iv, 16);

		if (flags & ENCRYPT)
			err =
			    crypto_blkcipher_encrypt(&desc, &sg, &sg,
						     PAGE_SIZE);
		else if (flags & DECRYPT)
			err =
			    crypto_blkcipher_decrypt(&desc, &sg, &sg,
						     PAGE_SIZE);

		if (err) {
			printk("error in encrypt/decrypt\n");
			err = -EIO;
			goto out;
		}

		size_written =
		    temp_outf->f_op->write(temp_outf, buf, size_read,
					   &temp_outf->f_pos);
		if (size_written == -1) {
			printk("failure to write to temp_outf\n");
			err = -EIO;
			goto out;
		}

		page_num++;
		memcpy(*iv, &page_num, 8);
	}
	if (size_read == -1) {
		printk("failure to read from inf\n");
		err = -EIO;
		goto out;
	}

      out:
	set_fs(fs);
	if (blkcipher && !IS_ERR(blkcipher))
		kfree(blkcipher);
	kfree(buf);

	return err;
}

/* This function writes the following to the preamble in case the file is being encryped.
   1) cipher name)
   2) hashed value of keybuf (the user passed key)
   3) Initial value of the iv which will be used for encryption

   Incase, the file is being decrypted, it does the following:
   1) reads the cipher name and validates it against the cipher name entered while decrypting
   2) reads the hashed key and validates it against the hashed value of the key passed while decrypting
   3) reads the initial value of the iv used while encrypting and sets it to *iv.

   In short, it proccesses the preamble section of the file.
*/
int process_preamble(struct file *inf, struct file *temp_outf,
		     char *cipher, unsigned char *keybuf, int keylen,
		     int flags, char **iv)
{
	unsigned char *keybuf_hash = NULL;
	int err = 0, size_written = 0, size_read = 0;
	char *pcipher = NULL, *pkey = NULL;
	u64 page_num = 1;

	keybuf_hash = md5hash(keybuf, keylen);
	if (IS_ERR(keybuf_hash)) {
		printk("error in generating md5hash from keybuf\n");
		err = PTR_ERR(keybuf_hash);
		goto out;
	}

	if (flags & ENCRYPT) {
		/* writing the cipher name */
		size_written =
		    temp_outf->f_op->write(temp_outf, cipher,
					   strlen(cipher) + 1,
					   &temp_outf->f_pos);
		if (size_written == -1) {
			printk("error writing cipher name to preamble\n");
			err = -EIO;
			goto out;
		}

		/* writing the hashed value of the user key */
		size_written =
		    temp_outf->f_op->write(temp_outf, keybuf_hash, 16,
					   &temp_outf->f_pos);
		if (size_written == -1) {
			printk("error writing keybuf_hash to preamble\n");
			err = -EIO;
			goto out;
		}

		/* writing the initial iv which will be used for encryption */
		*iv = get_iv(page_num, temp_outf->f_inode->i_ino);
		if (IS_ERR(*iv)) {
			err = PTR_ERR(*iv);
			goto out;
		}

		size_written =
		    temp_outf->f_op->write(temp_outf, *iv, 16,
					   &temp_outf->f_pos);
		if (size_written == -1) {
			printk("error writing iv to preamble\n");
			err = -EIO;
			goto out;
		}
	} else if (flags & DECRYPT) {
		/* reads the cipher name and validates it against the cipher name passed by the user */
		pcipher = kmalloc(strlen(cipher) + 1, GFP_KERNEL);
		if (pcipher == NULL) {
			printk("error while kmalloc for pcipher\n");
			err = -ENOMEM;
			goto out;
		}
		size_read =
		    inf->f_op->read(inf, pcipher, strlen(cipher) + 1,
				    &inf->f_pos);
		if (size_read == -1) {
			printk("error reading pcipher from preamble\n");
			err = -EIO;
			goto out;
		}

		if (strcmp(cipher, pcipher) != 0) {
			printk("different cipher used for encryption\n");
			err = -EINVAL;
			goto out;
		}

		/* reads the hashed value of the key used while encrypting and validates it against the hashed value of the user passed key. */
		pkey = kmalloc(16, GFP_KERNEL);
		if (pkey == NULL) {
			printk("error while kmalloc for pkey\n");
			err = -ENOMEM;
			goto out;
		}

		size_read = inf->f_op->read(inf, pkey, 16, &inf->f_pos);
		if (size_read == -1) {
			printk("error reading pkey from preamble\n");
			err = -EIO;
			goto out;
		}

		if (memcmp(keybuf_hash, pkey, keylen)) {
			printk
			    ("key passed for decyption is not the same as used while encryption.\n");
			err = -EINVAL;
			goto out;
		}

		/* reads the initial value of iv used while encrypting and sets it to *iv */
		*iv = kmalloc(16, GFP_KERNEL);
		if (*iv == NULL) {
			printk
			    ("error in allocating memory to iv in write\n");
			err = -ENOMEM;
			goto out;
		}

		size_read = inf->f_op->read(inf, *iv, 16, &inf->f_pos);
		if (size_read == -1) {
			printk("error reading iv from temp_outf\n");
			err = -EIO;
			goto out;
		}
	}

      out:
	if (!IS_ERR(keybuf_hash))
		kfree(keybuf_hash);
	kfree(pcipher);
	kfree(pkey);

	return err;
}

int xcrypt(struct job *job)
{
	struct xcrypt_config *xc = job->xcrypt_config;
	struct file *inf = NULL, *temp_outf = NULL;
	struct kstat stat_infile;
	char *outf_name = NULL, *temp_outfname = NULL, *iv = NULL;
	int err = 0;
	printk("Input file %s\n", xc->infile);
	err = vfs_stat(xc->infile, &stat_infile);
	if (err) {
		printk("error in vfs_stat for infile\n");
		goto out;
	}
	if (!S_ISREG(stat_infile.mode)) {
		printk("infile is not a regular file\n");
		err = -EINVAL;
		goto out;
	}
	inf = filp_open(xc->infile, O_RDONLY, 0);
	if (IS_ERR(inf)) {
		printk("error opening infile\n");
		err = PTR_ERR(inf);
		goto out;
	}

	outf_name = get_outfilename(xc->infile, xc->outfile, xc->flags);
	if (IS_ERR(outf_name)) {
		printk(KERN_ERR "error in get_outfilename\n");
		err = PTR_ERR(outf_name);
		goto out;
	}
	temp_outfname = get_tempfilename(outf_name);
	if (IS_ERR(temp_outfname)) {
		printk(KERN_ERR "error in get_tempfilename\n");
		err = PTR_ERR(temp_outfname);
		goto out;
	}
	temp_outf = filp_open(temp_outfname, O_WRONLY | O_CREAT, 0);
	if (IS_ERR(temp_outf)) {
		printk(KERN_ERR "error opening temp output file\n");
		err = -EINVAL;
		goto out;

	}

	if ((err =
	     process_preamble(inf, temp_outf, xc->cipher, xc->keybuf,
			      xc->keylen, xc->flags, &iv)))
		goto out;

	if ((err =
	     write(inf, temp_outf, xc->cipher, xc->keybuf, xc->keylen,
		   xc->flags, &iv)))
		goto out;

	process_outfile(inf, temp_outf, outf_name, xc->flags);
      out:
	kfree(xc->infile);
	kfree(xc->outfile);
	kfree(xc->cipher);
	kfree(xc->keybuf);
	kfree(xc);

	if (inf && !IS_ERR(inf))
		filp_close(inf, NULL);

	if (!IS_ERR(temp_outfname))
		kfree(temp_outfname);
	if (temp_outf && !IS_ERR(temp_outf)) {
		if (err)
			unlink(temp_outf);
		else
			filp_close(temp_outf, NULL);
	}

	if (iv && !IS_ERR(iv))
		kfree(iv);

	callback(job, err);
	kfree(job);

	return err;
}

struct xcrypt_config *alloc_xcrypt(struct xcrypt_config __user *
				   xcrypt_config)
{
	struct xcrypt_config *kxc = NULL;
	char *infile = NULL, *outfile = NULL, *cipher = NULL;
	unsigned char *keybuf = NULL;
	int err = 0;

	kxc = kmalloc(sizeof(struct xcrypt_config), GFP_KERNEL);
	if (kxc == NULL) {
		printk(KERN_ERR
		       "error while kmalloc for struct xcrypt_config\n");
		err = -ENOMEM;
		goto out;
	}
	if (copy_from_user
	    (kxc, xcrypt_config, sizeof(struct xcrypt_config))) {
		printk(KERN_ERR
		       "error copying struct xcrypt_config from user\n");
		err = -EINVAL;
		goto out;
	}

	if (xcrypt_config->infile != NULL) {
		infile = copy_string_from_usr(xcrypt_config->infile);
		if (infile == NULL) {
			printk(KERN_ERR
			       "error in copy_string_from_usr for infile\n");
			err = -EINVAL;
			goto out;
		}
		kxc->infile = infile;
	}

	if (xcrypt_config->outfile != NULL) {
		outfile = copy_string_from_usr(xcrypt_config->outfile);
		if (infile == NULL) {
			printk(KERN_ERR
			       "error in copy_string_from_usr for outfile\n");
			err = -EINVAL;
			goto out;
		}
		kxc->outfile = outfile;
	}

	if (xcrypt_config->cipher == NULL
	    || strlen_user(xcrypt_config->cipher) == 0) {
		printk
		    ("cipher name is NULL or cipher name length is 0, error.\n");
		err = -EINVAL;
		goto out;
	}
	cipher = kmalloc(strlen_user(xcrypt_config->cipher), GFP_KERNEL);
	if (cipher == NULL) {
		printk("error while kmalloc for cipher\n");
		err = -ENOMEM;
		goto out;
	}
	if (copy_from_user
	    (cipher, xcrypt_config->cipher,
	     strlen_user(xcrypt_config->cipher))) {
		printk("error while copying cipher from user\n");
		err = -EINVAL;
		goto out;
	}
	kxc->cipher = cipher;

	if (xcrypt_config->keylen == 0) {
		printk("hash key length is 0, error.\n");
		err = -EINVAL;
		goto out;
	}
	keybuf = kmalloc(xcrypt_config->keylen, GFP_KERNEL);
	if (keybuf == NULL) {
		printk("error while kmalloc for keybuf\n");
		err = -ENOMEM;
		goto out;
	}
	if (copy_from_user
	    (keybuf, xcrypt_config->keybuf, xcrypt_config->keylen)) {
		printk("error while copying keybuf from user\n");
		err = -EINVAL;
		goto out;
	}
	kxc->keybuf = keybuf;

      out:
	if (err) {
		kfree(infile);
		kfree(outfile);
		kfree(cipher);
		kfree(keybuf);
		return ERR_PTR(err);
	}

	return kxc;
}
