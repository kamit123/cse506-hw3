#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <asm/page.h>
#include <linux/syscalls.h>
#include <linux/fs_struct.h>
#include "job.h"
#include "util.h"


static void callback(struct job *job, int err, u8 *digest, int len)
{
	struct callback cb;
	cb.jobid = job->jobid;
	cb.result = err;
	if (err == 0) {
		memcpy(cb.msg, digest, len);
		cb.msglen = len;
	} else
		cb.msglen = 0;
	callback_socket(job->pid, cb);
}

int calculate_checksum_job(struct job *job)
{
	struct checksum_config *c_Config = job->checksum_config;
	char *filename = c_Config->filename;
	char *alg = c_Config->alg;
	unsigned int len = c_Config->hash_length;
	u8 *digest = NULL;
	struct scatterlist sg;
	struct hash_desc desc;
	struct file *filp = NULL;
	char *buf = NULL;
	int err = 0;
	loff_t i_size = 0;
	loff_t offset = 0;
	mm_segment_t oldfs;
	ssize_t rBytes = 0;

	filp = filp_open(filename, O_RDWR, 0);
	if (!filp || IS_ERR(filp)) {
		err = PTR_ERR(filp);
		filp = NULL;
		printk(KERN_ERR "filp open failed in checksum\n");
		goto out;
	}

	/*Read file */
	if (!(filp->f_mode & FMODE_READ)) {
		err = -EPERM;
		printk(KERN_ERR
		       "checksum:File does not have a read permission\n");
		goto out;
	}

	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL) {
		err = -ENOMEM;
		printk(KERN_ERR "checksum:  memory full\n");
		goto out;
	}

	digest = kzalloc(len, GFP_KERNEL);
	if (digest == NULL) {
		err = -ENOMEM;
		printk(KERN_ERR "Hash algorithm not defined\n");
		goto out;
	}

	desc.flags = 0;
	desc.tfm = crypto_alloc_hash(alg, 0, CRYPTO_ALG_ASYNC);
	if (!desc.tfm) {
		printk(KERN_ERR "Hash algorithm not defined\n");
		err = -EINVAL;
		goto out;
	}

	err = crypto_hash_init(&desc);
	if (err) {
		printk(KERN_ERR "error in crypto_hash_init in md5hash\n");
		goto out;
	}

	/*get read size of file in bytes */
	i_size = i_size_read(file_inode(filp));

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	/*Read till offset is less than i_size */
	while (offset < i_size) {
		rBytes = filp->f_op->read(filp, buf, PAGE_SIZE, &offset);
		if (rBytes < 0) {
			err = -EACCES;
			break;
		}

		if (rBytes == 0)
			break;
		sg_init_one(&sg, buf, rBytes);
		err = crypto_hash_update(&desc, &sg, rBytes);
		if (err) {
			printk(KERN_ERR
			       "error in crypto_hash_update in md5hash\n");
			break;
		}
	}
	set_fs(oldfs);
	if (!err) {
		err = crypto_hash_final(&desc, digest);
		if (err) {
			printk(KERN_ERR
			       "error in crypto_hash_final in md5hash\n");
		}
	}
	crypto_free_hash(desc.tfm);
      out:
	callback(job, err, digest, len);
	if (filp != NULL)
		filp_close(filp, 0);
	kfree(buf);
	kfree(digest);
	return err;
}

int checksum(struct job *job)
{
	struct checksum_config *checksum_Config = job->checksum_config;
	char *infile = checksum_Config->filename;
	struct kstat stat_infile;
	int err = 0;
	/*if error in vfs stat or reg file send err to netlink socket
	   else calculate_checksum will take care */
	int hack = 0;
	mm_segment_t oldfs;

	if (infile == NULL) {
		printk(KERN_ERR "Filename is Null in checksum.\n");
		err = -EINVAL;
		hack = 1;
		goto out;
	}
	printk(KERN_INFO "Filename is =%s.\n", infile);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_stat(infile, &stat_infile);
	if (err) {
		printk(KERN_ERR "error in vfs_stat for infile = %d\n",
		       err);
		set_fs(oldfs);
		hack = 1;
		goto out;
	}

	if (!S_ISREG(stat_infile.mode)) {
		printk(KERN_ERR "infile is not a regular file\n");
		err = -EINVAL;
		hack = 1;
		set_fs(oldfs);
		goto out;
	}
	set_fs(oldfs);
	err = calculate_checksum_job(job);
      out:
	if (hack == 1) {
		callback(job, err, NULL, 0);
	}
	dalloc_checksum(job);
	return err;
}

void dalloc_checksum(struct job *job)
{
	struct checksum_config *kconfig = job->checksum_config;
	kfree(kconfig->filename);
	kfree(kconfig->alg);
	kfree(kconfig);
	kfree(job);
}

struct checksum_config *alloc_checksum(struct checksum_config
				       *checksum_Config)
{
	struct checksum_config *cksum_Config = NULL;
	char *infile = NULL;
	char *ck_alg = NULL;
	int err = 0;

	cksum_Config = kzalloc(sizeof(struct checksum_config), GFP_KERNEL);
	if (cksum_Config == NULL) {
		printk(KERN_ERR
		       "error while kmalloc for struct checksum_config\n");
		err = -ENOMEM;
		goto out;
	}

	if (copy_from_user
	    (cksum_Config, checksum_Config,
	     sizeof(struct checksum_config))) {
		printk(KERN_ERR
		       "error copying struct checksum_Config from user\n");
		err = -EINVAL;
		goto out;
	}

	infile = copy_string_from_usr(checksum_Config->filename);
	if (infile == NULL) {
		printk(KERN_ERR "error in getting file\n");
		err = -EINVAL;
		goto out;
	}

	cksum_Config->filename = infile;
	ck_alg = copy_string_from_usr(checksum_Config->alg);

	if (cksum_Config->alg == NULL) {
		printk(KERN_ERR "error in getting file\n");
		err = -EINVAL;
		goto out;
	}

	cksum_Config->alg = ck_alg;
	return cksum_Config;
      out:
	kfree(infile);
	kfree(ck_alg);
	kfree(cksum_Config);
	return ERR_PTR(err);
}
