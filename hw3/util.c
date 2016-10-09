#include <linux/fs.h>
#include <asm/siginfo.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include "util.h"

char *copy_string_from_usr(char *usrStr)
{
	int len = 0;
	int sfur = 0;
	char *kernelString = NULL;
	if (usrStr == NULL) {
		printk(KERN_ERR "User string is NULL at %s, line %d. \n",
		       __FILE__, __LINE__);
		return NULL;
	}

	/*Length of usrStr */
	len = strnlen_user(usrStr, PATH_MAX);
	if (len == 0 || len > PATH_MAX) {
		printk(KERN_ERR "strnlen_user failed at %s, line %d.\n",
		       __FILE__, __LINE__);
		return NULL;
	}

	/*Allocate memory in kernel space */
	kernelString = kmalloc(len, GFP_KERNEL);

	/*Check if kmalloc failed */
	if (kernelString == NULL) {
		printk(KERN_ERR "Kmalloc failed at %s, line %d.\n",
		       __FILE__, __LINE__);
		return NULL;
	}

	/* Copy usrStr string from userspace to kernal space */
	sfur =
	    strncpy_from_user((void *) kernelString, (void *) usrStr,
			      PATH_MAX);

	/*Check if strncpy_from_user failed to copy string from userspace */
	if (sfur <= 0 || sfur == PATH_MAX) {
		printk(KERN_ERR
		       "strncpy_from_user failed at %s, line %d.\n",
		       __FILE__, __LINE__);
		return NULL;
	}

	return kernelString;
}

static int should_rename(int flags)
{
	if (flags & RENAME)
		return 1;
	else if (flags & REWRITE)
		return 0;

	return -1;
}

char *get_outfilename(char *infile, char *outfile, int flags)
{
	int renamef = should_rename(flags);
	if (renamef == 1)
		return outfile;
	else if (renamef == 0)
		return infile;
	else {
		printk(KERN_ERR
		       "error in flags, no option regarding rewr/ren specified\n");
		return ERR_PTR(-EINVAL);
	}
}

char *get_tempfilename(char *filename)
{
	char *temp;
	int err = 0;

	if (filename == NULL) {
		printk(KERN_ERR "filename is NULL in get_tempfilename\n");
		err = -EINVAL;
		goto out;
	}

	temp = kmalloc(strlen(filename) + 5, GFP_KERNEL);
	if (temp == NULL) {
		err = -ENOMEM;
		printk(KERN_ERR
		       "error allocating memory to temp in get_tempfilename\n");
		goto out;
	}
	memcpy(temp, filename, strlen(filename));
	memcpy(&temp[strlen(filename)], ".tmp\0", 5);

      out:
	if (err)
		return ERR_PTR(err);
	return temp;
}

void process_outfile(struct file *inf, struct file *temp_outf,
		     char *outf_name, int flags)
{
	struct file *outf;

	if (flags & REWRITE) {
		rename(temp_outf, inf);
	} else {
		outf = filp_open(outf_name, O_WRONLY | O_CREAT, 0);
		rename(temp_outf, outf);
	}
}

int rename(struct file *old, struct file *new)
{
	int err;
	struct dentry *old_dir_dentry = NULL, *new_dir_dentry =
	    NULL, *trap = NULL;

	old_dir_dentry = dget_parent(old->f_path.dentry);
	new_dir_dentry = dget_parent(new->f_path.dentry);

	trap = lock_rename(old_dir_dentry, new_dir_dentry);
	if (trap == old->f_path.dentry) {
		err = -EINVAL;
		goto out;
	}
	if (trap == new->f_path.dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err =
	    vfs_rename(old_dir_dentry->d_inode, old->f_path.dentry,
		       new_dir_dentry->d_inode, new->f_path.dentry, NULL,
		       0);
      out:
	dput(old_dir_dentry);
	dput(new_dir_dentry);
	unlock_rename(new_dir_dentry, old_dir_dentry);
	return err;
}

int unlink(struct file *victim)
{
	int err;
	struct dentry *dir_dentry = NULL;

	dir_dentry = dget_parent(victim->f_path.dentry);
	mutex_lock_nested(&dir_dentry->d_inode->i_mutex, I_MUTEX_PARENT);
	if (!&dir_dentry->d_inode->i_mutex) {
		printk("could not get lock on victim's parent dir\n");
		err = -ENOLCK;
		goto out;
	}

	err = vfs_unlink(dir_dentry->d_inode, victim->f_path.dentry, NULL);
	mutex_unlock(&dir_dentry->d_inode->i_mutex);

      out:
	dput(dir_dentry);
	return err;
}

int signal(int pid, int data)
{
	struct siginfo info;
	struct pid *pid_struct;
	struct task_struct *task;
	int err = 0;

	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = CALLBACK_SIG;
	info.si_code = SI_QUEUE;
	info.si_int = data;

	rcu_read_lock();
	pid_struct = find_get_pid(pid);
	if (pid_struct == NULL) {
		printk(KERN_ERR "could not find pid_struct for pid %d\n",
		       pid);
		err = -ENOENT;
		goto out;
	}
	task = pid_task(pid_struct, PIDTYPE_PID);
	if (task == NULL) {
		printk(KERN_ERR
		       "could not find task with pid %d to signal\n", pid);
		err = -ENOENT;
		goto out;
	}
	rcu_read_unlock();

	err = send_sig_info(44, &info, task);
	if (err) {
		printk(KERN_ERR
		       "error sending signal to process with pid %d\n",
		       pid);
		goto out;
	}

      out:
	return err;
}
