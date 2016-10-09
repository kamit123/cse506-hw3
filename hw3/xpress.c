#include <linux/fs.h>
#include <linux/crypto.h>
#include "job.h"
#include "util.h"

void dalloc_xpress(struct job *job)
{
	struct xpress_config *kxc = job->xpress_config;

	kfree(kxc->alg);
	kfree(kxc->infile);
	kfree(kxc->outfile);
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

static int get_bytes_to_decompress(struct file *inf)
{
	char nod[2], bytes[5];
	int size_read, err = 0, nodi, bytesi;

	size_read = inf->f_op->read(inf, nod, 1, &inf->f_pos);
	if (size_read <= 0) {
		err = -ENODATA;
		goto out;
	}
	nod[1] = '\0';
	err = kstrtoint(nod, 10, &nodi);
	if (err) {
		printk(KERN_ERR "error while kstrtoint\n");
		goto out;
	}

	size_read = inf->f_op->read(inf, bytes, nodi, &inf->f_pos);
	if (size_read <= 0) {
		err = -ENODATA;
		goto out;
	}
	bytes[nodi] = '\0';
	err = kstrtoint(bytes, 10, &bytesi);
	if (err) {
		printk(KERN_ERR "error while kstrtoint\n");
		goto out;
	}

	return bytesi;
      out:
	return err;
}

static int decompress(struct file *inf, struct file *temp_outf,
		      struct crypto_comp *tfm)
{
	char *rbuf = NULL, *wbuf = NULL;
	int err = 0, bytes_to_read, size_read, wbuf_len = PAGE_SIZE;

	rbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (rbuf == NULL) {
		printk(KERN_ERR "error in allocating memory to rbuf\n");
		err = -ENOMEM;
		goto out;
	}
	wbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (wbuf == NULL) {
		printk(KERN_ERR "error in allocating memory to wbuf\n");
		err = -ENOMEM;
		goto out;
	}

	bytes_to_read = get_bytes_to_decompress(inf);
	if (bytes_to_read == -ENODATA) {
		goto out;
	} else if (bytes_to_read < 0) {
		printk(KERN_ERR
		       "error while extracting bytes to decompress\n");
		err = bytes_to_read;
		goto out;
	}

	while ((size_read =
		inf->f_op->read(inf, rbuf, bytes_to_read,
				&inf->f_pos)) > 0) {
		crypto_comp_decompress(tfm, rbuf, size_read, wbuf,
				       &wbuf_len);
		temp_outf->f_op->write(temp_outf, wbuf, wbuf_len,
				       &temp_outf->f_pos);

		bytes_to_read = get_bytes_to_decompress(inf);
		if (bytes_to_read == -ENODATA) {
			goto out;
		} else if (bytes_to_read < 0) {
			printk(KERN_ERR
			       "error while extracting bytes to decompress\n");
			err = bytes_to_read;
			goto out;
		}
	}

      out:
	kfree(rbuf);
	kfree(wbuf);
	return err;
}

static int compress(struct file *inf, struct file *temp_outf,
		    struct crypto_comp *tfm)
{
	char *rbuf = NULL, *wbuf = NULL;
	int err = 0, size_read, wbuf_len = PAGE_SIZE;
	char nod[2], bytes[5];

	rbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (rbuf == NULL) {
		printk(KERN_ERR "error in allocating memory to rbuf\n");
		err = -ENOMEM;
		goto out;
	}
	wbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (wbuf == NULL) {
		printk(KERN_ERR "error in allocating memory to wbuf\n");
		err = -ENOMEM;
		goto out;
	}

	while ((size_read =
		inf->f_op->read(inf, rbuf, PAGE_SIZE, &inf->f_pos)) > 0) {
		crypto_comp_compress(tfm, rbuf, size_read, wbuf,
				     &wbuf_len);
		snprintf(bytes, 5, "%d", wbuf_len);
		snprintf(nod, 2, "%d", strlen(bytes));

		temp_outf->f_op->write(temp_outf, nod, 1,
				       &temp_outf->f_pos);
		temp_outf->f_op->write(temp_outf, bytes, strlen(bytes),
				       &temp_outf->f_pos);
		temp_outf->f_op->write(temp_outf, wbuf, wbuf_len,
				       &temp_outf->f_pos);
	}

      out:
	kfree(rbuf);
	kfree(wbuf);
	return err;
}

int xpress(struct job *job)
{
	int err = 0;
	struct file *inf = NULL, *temp_outf = NULL;
	char *outf_name = NULL, *temp_outfname = NULL;
	struct crypto_comp *tfm = NULL;
	mm_segment_t fs = get_fs();

	struct xpress_config *kxc = job->xpress_config;
	if (kxc->infile == NULL) {
		printk("infile received as NULL\n");
		err = -EINVAL;
		goto out;
	}
	inf = filp_open(kxc->infile, O_RDONLY, 0);
	if (IS_ERR(inf)) {
		printk(KERN_ERR "error opening infile\n");
		err = -EINVAL;
		goto out;

	}
	if (!S_ISREG(inf->f_inode->i_mode)) {
		printk(KERN_ERR "infile is not regular file\n");
		err = -EINVAL;
		goto out;

	}

	outf_name = get_outfilename(kxc->infile, kxc->outfile, kxc->flags);
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

	tfm = crypto_alloc_comp(kxc->alg, 0, 0);
	if (IS_ERR(tfm)) {
		printk("error in crypto_alloc_comp\n");
		err = PTR_ERR(tfm);
		goto out;
	}

	set_fs(get_ds());
	if (kxc->flags & COMPRESS)
		err = compress(inf, temp_outf, tfm);
	else if (kxc->flags & DECOMPRESS)
		err = decompress(inf, temp_outf, tfm);
	else {
		printk
		    ("error in xpress, neither compress nor decompress flag set\n");
		err = -EINVAL;
	}
	set_fs(fs);
	if (err)
		goto out;

	process_outfile(inf, temp_outf, outf_name, kxc->flags);
      out:
	kfree(kxc->infile);
	kfree(kxc->outfile);
	kfree(kxc);

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

	if (tfm && !IS_ERR(tfm))
		crypto_free_comp(tfm);

	if (job->callback_opt & CALLBACK_SOCKET)
		callback(job, err);
	if (job->callback_opt & CALLBACK_SIGNAL)
		signal(job->pid, err);
	kfree(job);

	return err;
}

struct xpress_config *alloc_xpress(struct xpress_config __user *
				   xpress_config)
{
	struct xpress_config *kxc = NULL;
	char *alg = NULL, *infile = NULL, *outfile = NULL;
	int err = 0;

	kxc = kmalloc(sizeof(struct xpress_config), GFP_KERNEL);
	if (kxc == NULL) {
		printk(KERN_ERR
		       "error while kmalloc for struct xpress_config\n");
		err = -ENOMEM;
		goto out;
	}
	if (copy_from_user
	    (kxc, xpress_config, sizeof(struct xpress_config))) {
		printk(KERN_ERR
		       "error copying struct xpress_config from user\n");
		err = -EINVAL;
		goto out;
	}

	if (xpress_config->alg != NULL) {
		alg = copy_string_from_usr(xpress_config->alg);
		if (alg == NULL) {
			printk(KERN_ERR
			       "error in copy_string_from_usr for infile\n");
			err = -EINVAL;
			goto out;
		}
		kxc->alg = alg;
	} else
		printk("alg name received as null\n");

	if (xpress_config->infile != NULL) {
		infile = copy_string_from_usr(xpress_config->infile);
		if (infile == NULL) {
			printk(KERN_ERR
			       "error in copy_string_from_usr for infile\n");
			err = -EINVAL;
			goto out;
		}
		kxc->infile = infile;
	}

	if (xpress_config->outfile != NULL) {
		outfile = copy_string_from_usr(xpress_config->outfile);
		if (infile == NULL) {
			printk(KERN_ERR
			       "error in copy_string_from_usr for outfile\n");
			err = -EINVAL;
			goto out;
		}
		kxc->outfile = outfile;
	}

      out:
	if (err) {
		kfree(alg);
		kfree(infile);
		kfree(outfile);
		return ERR_PTR(err);
	}

	return kxc;
}
