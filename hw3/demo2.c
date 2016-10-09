#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h> 
#include <string.h>
#include "job.h"

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

void recv_msg(int sock_fd, int pid)
{
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
        struct iovec iov;
        struct msghdr msg;
	struct callback *cb;
	int maxlen = sizeof(struct callback), len;

	memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = pid;
        bind(sock_fd,  (struct sockaddr *)&src_addr, sizeof(src_addr));

        memset(&dest_addr, 0, sizeof(dest_addr));

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(maxlen));
        memset(nlh, 0, NLMSG_SPACE(maxlen));

        iov.iov_base = (void *)nlh;
        iov.iov_len = NLMSG_SPACE(sizeof(struct callback));
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

	len = recvmsg(sock_fd, &msg, 0);
	if(len < 0)
		printf("Error receiving message from the kernel\n");
	else{
		cb = (struct callback *)NLMSG_DATA(msg.msg_iov->iov_base);
		printf("Message from kernel: %d\n", cb->result);
	}	

	free(nlh);
}

void create_task_config(struct job* job,int jobid,int pid)
{
    struct task_config tasks;
    tasks.jobid = jobid;
    tasks.pid =pid;
    job->task_config = tasks;

}

int main(int argc, char *const argv[])
{
	int err = 0;
	//int sock_fd;	
	struct job *job;
	struct xpress_config *xc;
	struct checksum_config *cc;
	int iter = 0;
	job = malloc(sizeof(struct job));
	xc = malloc(sizeof(struct xpress_config));
	cc = malloc(sizeof(struct checksum_config));
	xc->alg = "deflate";
	xc->infile = "/root/Avatar.mkv";
	xc->outfile = "/usr/src/hw3-cse506g06/hw3/Avt_dec.txt";
	xc->flags = COMPRESS | RENAME;
	job->pid = getpid();
	job->type = XPRESS;
	job->xpress_config = xc;
	job->priority = 1;
	#if 0
	sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
	if (sock_fd < 0){
		printf("error creating socket\n");
		err = sock_fd;
		goto out;
	}
	#endif
	printf("Before comprression\n");
	err = syscall(__NR_submitjob, job);
	if (err == 0)
	    printf("syscall returned %d\n", err);
	else
	    perror("Result of submitjob syscall");

	/*Checksum*/
	job->type = CHECKSUM;
	job->pid = getpid();
	job->priority = 5;
	cc->filename = "/root/Avatar.mkv";
	cc->alg = "sha1";
	cc->hash_length = 20;
	job->checksum_config = cc;
	for(iter =0;iter<15;iter++)
	{
	    job->priority = 15-iter;
	    job->jobid = iter;
	    printf("Before checksum%d\n",iter);
	    err = syscall(__NR_submitjob, job);
	    if (err == 0)
		printf("syscall returned %d\n", err);
	    else
		perror("Result of submitjob syscall");
	}
	/*List job*/
	job->type = LIST;
	err = syscall(__NR_submitjob, job);
	printf("Before list\n");
	if (err == 0)
	    printf("syscall returned %d\n", err);
	else
	    perror("Result of submitjob syscall");
	if(job->type == LIST)
	{
	    printf("JOBID|PID\n");
	    printf("%s\n",job->task_config.buf);

	}

	#if 0
	recv_msg(sock_fd, getpid());
	
	close(sock_fd);
	#endif
	free(xc);
	free(cc);
	free(job);
	return err;
}	
