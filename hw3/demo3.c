#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h> 
#include <string.h>
#include "job.h"
#include <pthread.h>

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

#define NUM_CHK 2
#define NUM_JOB NUM_CHK+1

void recv_msg(void *arg)
{
    int *sock_fd = (int *)arg;
    int len, i, maxlen = sizeof(struct callback);
    struct sockaddr_nl dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    struct callback *cb;
    int job = 0;
    memset(&dest_addr, 0, sizeof(dest_addr));

    nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(maxlen));
    memset(nlh, 0, NLMSG_SPACE(maxlen));

    iov.iov_base = (void *) nlh;
    iov.iov_len = NLMSG_SPACE(sizeof(struct callback));
    msg.msg_name = (void *) &dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    while(1)
    {
	len = recvmsg(*sock_fd, &msg, 0);
	job++;
	if (len < 0){
	    printf("Error receiving message from the kernel:%d\n", len);
	    perror("Result of submitjob syscall");
	}
	else {
	    cb = (struct callback *) NLMSG_DATA(msg.msg_iov->
		    iov_base);
	    printf("Message from kernel: %d\n", cb->result);
	    if (cb->msglen > 0) {
		for (i = 0; i < cb->msglen; i++)
		    printf("%02x ", cb->msg[i]);
		printf("\n");

	    }
	}
	if(job == NUM_JOB)
	    break;
    }

    close(*sock_fd);
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
        int err = 0,sock_fd;
	struct sockaddr_nl src_addr;
	pthread_t st = -1;
	struct job *job;
	struct xpress_config *xc;
	struct checksum_config *cc;
	int iter = 0;
	sock_fd = socket(AF_NETLINK, SOCK_RAW, SOCKET_PROTOCOL);
	if (sock_fd < 0) {
	    printf("error creating socket\n");
	    exit(-1);
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	if(bind(sock_fd, (struct sockaddr *) &src_addr, sizeof(src_addr))){
	    printf("error in bind\n");
	    exit(-1);
	}
	job = malloc(sizeof(struct job));
	xc = malloc(sizeof(struct xpress_config));
	cc = malloc(sizeof(struct checksum_config));

	xc->infile = "/usr/src/hw3-cse506g06/hw3/input1.txt";
	xc->outfile = "/usr/src/hw3-cse506g06/hw3/output1.txt";
	xc->flags = COMPRESS | RENAME;
	xc->alg = "deflate";
	job->pid = getpid();
	job->type = XPRESS;
	job->xpress_config = xc;
	job->priority = 1;
	job->callback_opt = CALLBACK_SOCKET;	

	pthread_create(&st, NULL, (void *) &recv_msg, &sock_fd);
	err = syscall(__NR_submitjob, job);
	if (err == 0)
	    printf("syscall returned %d\n", err);
	else
	    perror("Result of submitjob syscall");
	/*Checksum*/
	job->type = CHECKSUM;
	job->pid = getpid();
	job->priority = 5;
	cc->filename = "/usr/src/hw3-cse506g06/hw3/input1.txt";
	cc->alg = "sha1";
	cc->hash_length = 20;
	job->checksum_config = cc;
	for(iter =0;iter<NUM_CHK;iter++)
	{
	    job->priority = 15-iter;
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
	pthread_join(st, NULL);
	free(xc);
	free(cc);
	free(job);
	return err;
}	
