#include <linux/fs.h>
#include <linux/crypto.h>
#include "job.h"
#include "util.h"

static void callback(struct job *job, int err)
{
	struct callback cb;
	cb.jobid = job->jobid;
	cb.result = err;
	cb.msglen = 0;
	callback_socket(job->pid, cb);
}

static void process_outfile_concat(struct file *temp_outf, char *outf_name)
{
	struct file *outf;

	outf = filp_open(outf_name, O_WRONLY | O_CREAT, 0);
	rename(temp_outf, outf);
}

int concat(struct job *job)
{
	struct concate_config *kconcfg = job->concate_config;
	int err = 0;
	int i = 0;
	int num_files = 0;
	struct file *infile1 = NULL;
	struct file *temp_outf = NULL;
	char *temp_outfname = NULL;
	mm_segment_t oldfs;
	char *buf = NULL;
	ssize_t bytes = 0;
	ssize_t outbytes = 0;

	num_files = kconcfg->flag;

	temp_outfname = get_tempfilename(kconcfg->outfile);
	if (IS_ERR(temp_outfname)) {
		printk(KERN_ERR "error in get_tempfilename\n");
		err = PTR_ERR(temp_outfname);
		goto out;
	}

	temp_outf = filp_open(temp_outfname, O_CREAT | O_WRONLY, 644);
	if (IS_ERR(temp_outf)) {
		printk(KERN_ERR "error opening temp output file\n");
		err = -EINVAL;
		goto out;

	}



	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		return -ENOMEM;
		goto out;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);


	for (i = 0; i < num_files; i++) {

		infile1 = filp_open(kconcfg->infile[i], O_RDONLY, 0);
		if (!infile1 || IS_ERR(infile1)) {
			printk("Error in opening input file %d\n",
			       (int) PTR_ERR(infile1));
			err = PTR_ERR(infile1);
			goto rw_fail;
		}

		if (!S_ISREG(infile1->f_inode->i_mode)) {
			printk(KERN_ERR "infile is not regular file\n");
			err = -EINVAL;
			goto rw_fail;

		}

		infile1->f_pos = 0;
		while (1) {
			bytes =
			    vfs_read(infile1, buf, PAGE_SIZE,
				     &infile1->f_pos);
			if (bytes == -1) {
				err = -1;
				printk
				    ("Failed during reading data from file\n");
				goto rw_fail;
			}

			if (!bytes) {
				printk("file read completely\n");
				break;
			}

			outbytes =
			    vfs_write(temp_outf, buf, bytes,
				      &temp_outf->f_pos);
			if (outbytes == -1) {
				err = -1;
				printk
				    ("Failed during writing key into file header\n");
				goto rw_fail;
			}
			memset(buf, 0, PAGE_SIZE);
		}
		if (!IS_ERR(infile1))
			filp_close(infile1, 0);
	}

	set_fs(oldfs);
	process_outfile_concat(temp_outf, kconcfg->outfile);

	goto out;



rw_fail:
	unlink(temp_outf);

out:
	callback(job, err);
	if (!IS_ERR(temp_outf))
		filp_close(temp_outf, 0);
	kfree(buf);
	for (i = 0; i < num_files; i++) {
		kfree(kconcfg->infile[i]);
	}
	kfree(kconcfg->outfile);
	kfree(temp_outfname);
	kfree(kconcfg->infile);
	kfree(kconcfg);
	kfree(job);

	return err;
}

struct concate_config *alloc_concat(struct concate_config *concfg)
{
	struct concate_config *kconcfg;
	int err = 0;
	int i = 0;
	int num_files = 0;
	int length = 0;

	kconcfg = kmalloc(sizeof(struct concate_config), GFP_KERNEL);
	if (kconcfg == NULL) {
		printk("Error allocating memory to job\n");
		err = -ENOMEM;
		goto out;
	}

	if (copy_from_user(kconcfg, concfg, sizeof(struct concate_config))) {
		printk("error copying struct job from user\n");
		err = -EINVAL;
		goto out;
	}
	num_files = kconcfg->flag;

	kconcfg->infile = kmalloc(4 * num_files, GFP_KERNEL);
	if (kconcfg->infile == NULL) {
		printk("Error allocating memory to infile\n");
		err = -ENOMEM;
		goto out;
	}

	if (copy_from_user(kconcfg->infile, concfg->infile, 4 * num_files)) {
		printk("error copying infile from user\n");
		err = -EINVAL;
		goto out;
	}


	for (i = 0; i < num_files; i++) {

		length = strlen_user(concfg->infile[i]);
		kconcfg->infile[i] = kmalloc(length, GFP_KERNEL);
		if (kconcfg->infile[i] == NULL) {
			printk("Error allocating memory to infile1\n");
			err = -ENOMEM;
			goto out;
		}
		if (copy_from_user
		    (kconcfg->infile[i], concfg->infile[i], length)) {
			printk("error copying infile1 from user\n");
			err = -EINVAL;
			goto out;
		}


	}


	kconcfg->outfile =
	    kmalloc(strlen_user(concfg->outfile), GFP_KERNEL);
	if (kconcfg->outfile == NULL) {
		printk("Error allocating memory to outfile\n");
		err = -ENOMEM;
		goto out;
	}
	if (copy_from_user
	    (kconcfg->outfile, concfg->outfile,
	     strlen_user(concfg->outfile))) {
		printk("error copying outfile from user\n");
		err = -EINVAL;
		goto out;
	}


	return kconcfg;
out:
	for (i = 0; i < num_files; i++) {
		kfree(kconcfg->infile[i]);
	}
	kfree(kconcfg->outfile);
	kfree(kconcfg->infile);
	kfree(kconcfg);
	return ERR_PTR(err);

}


void dalloc_concat(struct job *job)
{
	struct concate_config *kconcfg = job->concate_config;
	int num_files = kconcfg->flag;
	int i = 0;

	for (i = 0; i < num_files; i++) {
		kfree(kconcfg->infile[i]);
	}
	kfree(kconcfg->outfile);
	kfree(kconcfg->infile);
	kfree(kconcfg);

	kfree(job);
}
