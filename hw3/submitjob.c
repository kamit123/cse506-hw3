#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include "job.h"
#include "util.h"

asmlinkage extern long (*sysptr) (void *arg);

struct sock *netlink_sock;
struct work *head = NULL;
int count = 0;
struct task_struct *producer_task = NULL;
static DECLARE_WAIT_QUEUE_HEAD(producer_queue);
static DECLARE_WAIT_QUEUE_HEAD(consumer_queue);
int producer_count = 0;
#define NUM_OF_CONSUMERS 2
#define NUM_OF_PRODUCER 2
struct task_struct *consumer_task[NUM_OF_CONSUMERS];

/*Mutex to lock workqueue and count*/
struct mutex wq_mutex;
int insertWork(struct job *job)
{
	int priority = job->priority;
	struct work *curr = head;
	struct work *tmp = NULL;
	struct work *prev = NULL;
	int err = 0;

	tmp = kmalloc(sizeof(struct work), GFP_KERNEL);
	if (tmp == NULL) {
		printk(KERN_ERR "Memory not available\n");
		err = -ENOMEM;
		goto out;
	}

	tmp->data = job;
	tmp->next = NULL;

	if (head == NULL) {
		head = tmp;
	} else {
		while (curr != NULL) {
			if (curr->data->priority > priority) {
				printk(KERN_INFO
				       "Found place to insert work");
				break;
			}
			prev = curr;
			curr = curr->next;
		}
		/*Place is at head so update head */
		if (prev == NULL) {
			tmp->next = head;
			head = tmp;
		} else {
			tmp->next = curr;
			prev->next = tmp;
		}
	}
out:
	return err;
}

/*jobid: JobId
pid: Process ID
 */
struct work *removework(int jobid, int pid)
{
	struct work *curr = head;
	struct work *tmp = NULL;
	struct work *prev = NULL;
	int err = 0;
	int found = 0;
	while (curr != NULL) {
		if (curr->data->jobid == jobid && curr->data->pid == pid) {
			found = 1;
			break;
		}
		prev = curr;
		curr = curr->next;
	}
	if (found) {
		tmp = curr;
		/*If job is at head then update head */
		if (prev == NULL)
			head = curr->next;
		else
			prev->next = curr->next;
		tmp->next = NULL;
	} else {
		printk(KERN_ERR "Job not found.\n");
		err = -EINVAL;
	}
	if (err)
		return ERR_PTR(err);
	return tmp;
}


int callback_socket(int pid, struct callback cb)
{
	int err = 0, len = sizeof(cb);
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh;

	skb = nlmsg_new(NLMSG_ALIGN(len), GFP_KERNEL);
	if (skb == NULL) {
		printk("error in nlmsg_new for pid:%d\n", pid);
		err = -EIO;
		goto out;
	}

	nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, len, 0);
	if (nlh == NULL) {
		printk("error in nlmsg_put for pid:%d\n", pid);
		err = -EIO;
		goto out;
	}
	memcpy(nlmsg_data(nlh), &cb, len);

	err = nlmsg_unicast(netlink_sock, skb, pid);
	if (err) {
		printk("error sending message to pid:%d\n", pid);
		goto out;
	}
out:
	return err;
}

int list_pending_jobs(char *user_buf)
{

	int listSize = 4096;
	char temp[10];
	char temp1[10];
	char temp2[10];
	char *kbuf = NULL;
	struct work *pos = head;
	int err = 0;
	kbuf = kmalloc(listSize, GFP_KERNEL);
	if (!kbuf) {
		err = -ENOMEM;
		goto out;
	}
	memset(kbuf, 0, listSize);
	mutex_lock(&wq_mutex);
	while (pos != NULL) {
		snprintf(temp, 10, "%d", pos->data->jobid);
		snprintf(temp1, 10, "%d", pos->data->pid);
		snprintf(temp2, 10, "%d", pos->data->priority);
		strcat(kbuf, temp);
		strcat(kbuf, "|");
		strcat(kbuf, temp1);
		strcat(kbuf, "|");
		strcat(kbuf, temp2);
		strcat(kbuf, "\n");
		pos = pos->next;
	}
	mutex_unlock(&wq_mutex);
	/*Remove the last \n added by the above loop */
	kbuf[strlen(kbuf) - 1] = '\0';

	if (copy_to_user(user_buf, kbuf, strlen(kbuf))) {
		printk(KERN_ERR "Error copying data to user");
		err = -EFAULT;
	}
out:
	if (kbuf)
		kfree(kbuf);
	return err;

}

void free_list(void)
{
	struct work *curr = head;
	struct work *pos = NULL;
	int type = -1;
	mutex_lock(&wq_mutex);

	while (curr != NULL) {

		pos = curr;
		curr = curr->next;
		type = pos->data->type;
		count--;

		switch (type) {

		case CONCATENATE:
			dalloc_concat(pos->data);
			break;

		case XPRESS:
			dalloc_xpress(pos->data);
			break;

		case CHECKSUM:
			dalloc_checksum(pos->data);
			break;

		case XCRYPT:
			dalloc_xcrypt(pos->data);
			break;

		}
		kfree(pos);
	}
	mutex_unlock(&wq_mutex);
}

int remove_job(struct task_config taskcfg)
{
	int err = 0;
	int type = -1;
	struct work *pos = NULL;
	mutex_lock(&wq_mutex);
	pos = removework(taskcfg.jobid, taskcfg.pid);
	if (!IS_ERR(pos)) {
		type = pos->data->type;
		count--;
	}
	mutex_unlock(&wq_mutex);
	switch (type) {

	case CONCATENATE:
		dalloc_concat(pos->data);
		break;

	case XPRESS:
		dalloc_xpress(pos->data);
		break;

	case CHECKSUM:
		dalloc_checksum(pos->data);
		break;

	case XCRYPT:
		dalloc_xcrypt(pos->data);
		break;

	default:
		err = -EINVAL;
		printk(KERN_ERR "Invalid Job Type :%d\n", type);
		goto out;
	}
	kfree(pos);
out:
	return err;
}

int modify_priority(struct job *job)
{
	struct task_config taskcfg = job->task_config;
	struct work *pos = NULL;
	struct job *kjob = NULL;
	int err = 0;

	mutex_lock(&wq_mutex);
	pos = removework(taskcfg.jobid, taskcfg.pid);
	if (IS_ERR(pos)) {
		err = -EINVAL;
		goto out;
	} else {
		kjob = pos->data;
		kjob->priority = job->priority;
		insertWork(kjob);
		kfree(pos);
	}
out:
	mutex_unlock(&wq_mutex);
	return err;
}

int process_request(struct job *job)
{
	int err = 0;
	printk("Inside process request.\n");
	printk("job id is = %d.\n", job->type);

	if (job->type == CHECKSUM)
		err = checksum(job);
	else if (job->type == XPRESS)
		err = xpress(job);
	else if (job->type == CONCATENATE)
		err = concat(job);
	else if (job->type == XCRYPT) {
		err = xcrypt(job);
	} else
		printk(KERN_ERR "job ID is not valid.\n");
	return err;
}

int consumer(void *data)
{
	int err = 0;
	struct work *pos = NULL;
	struct job *tmp_job = NULL;
	while (1) {
		wait_event_interruptible(consumer_queue, count > 0);
		if (kthread_should_stop()) {
			printk("[Consumer:]a2\n");
			break;
		} else {
			mutex_lock(&wq_mutex);
		}
		printk(KERN_ERR "Consumer thread_ID is =%d \n",
		       current->pid);
		pos = removework(head->data->jobid, head->data->pid);
		tmp_job = pos->data;
		count--;
		printk("[Consumer:]count is =%d \n", count);
		if (count == MAX_JOB - 1) {
			printk(KERN_ERR
			       " [Consumer:] Wake up producer.\n ");
			wake_up_interruptible(&producer_queue);
		}
		mutex_unlock(&wq_mutex);
		printk(KERN_ERR "[Consumer:]Job ID is =%d \n",
		       tmp_job->type);
		err = process_request(tmp_job);
		kfree(pos);
	}
	return err;
}

int producer(void *data)
{
	int err = 0;
	struct job *ktmp_job = NULL;
	ktmp_job = (struct job *) data;

	mutex_lock(&wq_mutex);
	/* do the work with the data you're protecting */
	if (count >= MAX_JOB) {
		printk(KERN_ERR
		       "Max job limit reached. Put producer thread in wait queue\n");
		mutex_unlock(&wq_mutex);
		producer_count++;
		wait_event_interruptible(producer_queue, count < MAX_JOB);
		producer_count--;
		mutex_lock(&wq_mutex);
	}
	insertWork(ktmp_job);
	count++;
	printk("[producer:]count is =%d \n", count);
	if (count == 1) {
		printk(KERN_ERR
		       "[Producer:]Count reached 1 wakeup consumer thread\n");
		wake_up_interruptible(&consumer_queue);
	}
	mutex_unlock(&wq_mutex);
	return err;
}

asmlinkage long submitjob(void *arg)
{
	struct job *job = NULL;
	struct job *kjob = NULL;
	int err = 0;

	job = (struct job *) arg;
	if (job->type == CHECKSUM || job->type == XPRESS
	    || job->type == XCRYPT || job->type == CONCATENATE) {
		if (producer_count == NUM_OF_PRODUCER) {
			printk("All Producers are busy.\n");
			err = -EFAULT;
			goto out;
		}
	}


	kjob = kmalloc(sizeof(struct job), GFP_KERNEL);
	if (kjob == NULL) {
		printk(KERN_ERR "error while kmalloc for struct job\n");
		err = -ENOMEM;
		goto out;
	}

	if (copy_from_user(kjob, job, sizeof(struct job))) {
		printk("error copying struct job from user\n");
		err = -EINVAL;
		goto out;
	}
	switch (kjob->type) {
	case CHECKSUM:
		kjob->checksum_config =
		    alloc_checksum(job->checksum_config);
		if (IS_ERR(kjob->checksum_config)) {
			printk(KERN_ERR
			       "Error while copying checksum config.\n");
			err = -EFAULT;
			goto out;
		}
		printk(KERN_INFO "Submitjob: Filename is =%s.\n",
		       kjob->checksum_config->filename);
		break;

	case XPRESS:
		kjob->xpress_config = alloc_xpress(job->xpress_config);
		if (IS_ERR(kjob->xpress_config)) {
			printk(KERN_ERR
			       "Error while copying xpress config.\n");
			err = -EFAULT;
			goto out;
		}
		break;
	case XCRYPT:
		kjob->xcrypt_config = alloc_xcrypt(job->xcrypt_config);
		if (IS_ERR(kjob->xcrypt_config)) {
			printk(KERN_ERR
			       "Error while copying xcrypt config.\n");
			err = -EFAULT;
			goto out;
		}
		break;

	case CONCATENATE:
		kjob->concate_config = alloc_concat(job->concate_config);
		if (IS_ERR(kjob->concate_config)) {
			printk(KERN_ERR
			       "Error while copying concate config.\n");
			err = -EFAULT;
			goto out;
		}
		break;

	case LIST:
		err = list_pending_jobs(job->task_config.buf);
		if (err)
			printk(KERN_ERR
			       "Error in listing the pending jobs.\n");
		kfree(kjob);
		goto out;
	case REMOVE:
		err = remove_job(job->task_config);
		if (err)
			printk(KERN_ERR "Error in removing jobs.\n");
		kfree(kjob);
		goto out;
	case MODIFY:
		err = modify_priority(kjob);
		if (err)
			printk(KERN_ERR "Error in modifing priority.\n");
		kfree(kjob);
		goto out;
	default:
		printk(KERN_ERR "feature not supported%d\n", kjob->type);
		goto out;
	}
	producer_task =
	    kthread_run(&producer, kjob, "producer%d", kjob->jobid);
out:
	return err;
}


static int __init init_sys_submitjob(void)
{
	int err = 0;
	int th_id = 0;
	if (sysptr == NULL) {
		sysptr = submitjob;

		netlink_sock =
		    netlink_kernel_create(&init_net, SOCKET_PROTOCOL,
					  NULL);
		if (netlink_sock == NULL) {
			printk("error while creating netlink socket\n");
			err = -EIO;
			goto out;
		}

		/*Mutex initiliazation */
		mutex_init(&wq_mutex);
		for (th_id = 0; th_id < NUM_OF_CONSUMERS; th_id++) {
			consumer_task[th_id] =
			    kthread_run(&consumer, NULL, "consumer%d",
					th_id + 1);
		}
	}

out:
	if (err == 0)
		printk("installed new sys_submitjob module\n");
	return err;
}
static void __exit exit_sys_submitjob(void)
{
	int th_id = 0;
	if (sysptr != NULL) {
		free_list();
		count = 1;
		for (th_id = 0; th_id < NUM_OF_CONSUMERS; th_id++) {
			if (consumer_task[th_id] != NULL)
				kthread_stop(consumer_task[th_id]);
		}
		netlink_kernel_release(netlink_sock);
		sysptr = NULL;
	}
	printk("removed sys_submit module\n");
}

module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
