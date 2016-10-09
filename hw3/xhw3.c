#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <openssl/md5.h>
#include "job.h"

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

#define SHA1_ALG "sha1"
#define MD5_ALG "md5"
#define MD5_LEN 16
#define SHA1_LEN 20
#define MAX_PATH 1024

int signal_recvd = 0;

char *getPath(char *input)
{
	if (input == NULL)
		return NULL;

	char* cwd;
	char buff[MAX_PATH + 1];

    	cwd = getcwd(buff, sizeof(buff));
      	
	if(input[0] == '/')
		return input;
	else {
	   strcat(cwd,"/");
	   strcat(cwd,input);
	   return cwd;
	}
}


void create_task_config(struct job *job, int jobid, int pid)
{
	struct task_config tasks;
	tasks.jobid = jobid;
	tasks.pid = pid;
	job->task_config = tasks;

}

int alloc_xpress(struct job *job, char *alg, char *input, char *output,
		 int xpress, int cl_netlink)
{
	struct xpress_config *xc = NULL;
	int err = 0;
	char *input_cwd, *output_cwd = NULL;
	xc = malloc(sizeof(struct xpress_config));
	if (xc == NULL) {
		printf("Error allocating memory to xc\n");
		err = -ENOMEM;
		goto out;
	}

	xc->alg = alg;
	input_cwd = getPath(input);
        xc->infile = malloc(strlen(input_cwd)+1);
        strcpy(xc->infile, input_cwd);

        if (output != NULL){
                output_cwd = getPath(output);
                xc->outfile = malloc(strlen(output_cwd)+1);
                strcpy(xc->outfile, output_cwd);
        }
	else
		xc->outfile = NULL;

	if (output == NULL && xpress)
		xc->flags = COMPRESS | REWRITE;
	else if (output != NULL && xpress)
		xc->flags = COMPRESS | RENAME;
	else if (output == NULL && !xpress)
		xc->flags = DECOMPRESS | REWRITE;
	else if (output != NULL && !xpress)
		xc->flags = DECOMPRESS | RENAME;


	if (cl_netlink == 0)
		job->callback_opt = CALLBACK_SIGNAL;
	else
		job->callback_opt = CALLBACK_SOCKET;

      out:
	job->xpress_config = xc;
	
	return err;
}

void free_xpress(struct xpress_config *xc)
{
	free(xc->infile);
	if(xc->outfile != NULL)
                free(xc->outfile);
	free(xc);
}

int alloc_xcrypt(struct job *job, char *alg, char *password, char *input, char *output,
                 int xcrypt)
{
        struct xcrypt_config *xc = NULL;
        int err = 0;
	char *input_cwd, *output_cwd = NULL;
	MD5_CTX context;
        unsigned char digest[16];

        xc = malloc(sizeof(struct xcrypt_config));
        if (xc == NULL) {
                printf("Error allocating memory to xc\n");
                err = -ENOMEM;
                goto out;
        }

        xc->cipher = alg;
	
	input_cwd = getPath(input);
	xc->infile = malloc(strlen(input_cwd)+1);
	strcpy(xc->infile, input_cwd);
	
	if (output != NULL){
		output_cwd = getPath(output);
		xc->outfile = malloc(strlen(output_cwd)+1);
		strcpy(xc->outfile, output_cwd);
	}
	else
                xc->outfile = NULL;

        if (output == NULL && xcrypt)
                xc->flags = ENCRYPT | REWRITE;
        else if (output != NULL && xcrypt)
                xc->flags = ENCRYPT | RENAME;
        else if (output == NULL && !xcrypt)
                xc->flags = DECRYPT | REWRITE;
        else if (output != NULL && !xcrypt)
                xc->flags = DECRYPT | RENAME;

	if(!MD5_Init(&context)){
                printf("Error in MD5_Init (generating hash from password)\n");
                err = -1;
                goto out;
        }
        if(!MD5_Update(&context, password, strlen(password))){
                printf("Error in MD5_Init (generating hash from password)\n");
                err = -1;
                goto out;
        }
        if(!MD5_Final(digest, &context)){
                printf("Error in MD5_Init (generating hash from password)\n");
                err = -1;
                goto out;
        }
	
	xc->keybuf = malloc(16);
	memcpy(xc->keybuf, digest, 16);
	xc->keylen = 16;

      out:
        job->xcrypt_config = xc;
        return err;
}

void free_xcrypt(struct xcrypt_config *xc)
{
	free(xc->infile);
	if(xc->outfile != NULL)
		free(xc->outfile);
	free(xc->keybuf);
        free(xc);
}



int create_concat_config(struct job *job, char *input, char *output)
{
	struct concate_config *cjob = NULL;
	int err = 0;
	int i = 0;
	int num_files = 1;
	char *file = NULL;
	char *tmp =NULL;
	char **infiles = NULL;
	char *outfile = NULL;
	int out_length = 0;
	char *input_list = NULL;
	char *a = NULL;
	int length = 0;

	cjob = malloc(sizeof(struct concate_config));
	if (cjob == NULL) {
		job->concate_config = NULL;
		printf("Error allocating memory to concate job\n");
		return -ENOMEM;
	}
	cjob->infile = NULL;
	cjob->outfile = NULL;
	length = strlen(input);
	out_length = strlen(output);
	input_list = (char *) malloc(length + 1);
	if (input_list == NULL) {
		printf("Error allocating memory to inputfile1\n");
		err = -1;
		goto out;
	}

	strcpy(input_list, input);
	a = input_list;
	while (*a != '\0') {
		if (*a == ',')
			num_files++;
		a++;
	}


	infiles = (char **) calloc(num_files, sizeof(char *));
	if (infiles == NULL) {
		printf("Error allocating memory to inputfile\n");
		err = -1;
		goto out;
	}


	while ((file = strsep(&input_list, ",")) != NULL) {
		if (!*file)
			continue;
		tmp = getPath(file);
		infiles[i] = (char *) malloc(strlen(tmp) + 1);
		if (infiles[i] == NULL) {
			printf("Error allocating memory to infile\n");
			err = -1;
			goto out;
		}
		strcpy(infiles[i], tmp);
		i++;
		tmp = NULL;
	}

	cjob->infile = infiles;

	
	tmp = getPath(output);
	outfile = (char *) malloc(strlen(tmp) + 1);
	if (outfile == NULL) {
		printf("Error allocating memory to outfile\n");
		err = -1;
		goto out;
	}
	
	strcpy(outfile, tmp);
	cjob->outfile = outfile;
	cjob->flag = num_files;
out:
	job->concate_config = cjob;
	if (input_list != NULL)
		free(input_list);
	return err;
}

void free_concat_config(struct concate_config *cc)
{
	int i;
	int num_files = cc->flag;
	for (i = 0; i < num_files; i++) {
		free(cc->infile[i]);
	}
	if (cc->outfile != NULL)
		free(cc->outfile);
	free(cc);
}

int alloc_checksum(struct job *job, char *alg, char *infile)
{
	int len;
	char *tmp;
	int err = 0;
	struct checksum_config *cc = NULL;
	if (strcmp(alg, SHA1_ALG) == 0) {
		len = SHA1_LEN;
	} else if (strcmp(alg, MD5_ALG) == 0)
		len = MD5_LEN;
	else {
		printf("User gave wrong algo name.\n");
		return -1;
	}
	cc = malloc(sizeof(struct checksum_config));
	if (cc == NULL) {
		printf("Error allocating memory to checksum\n");
		err = -ENOMEM;
		goto out;
	}
	tmp = getPath(infile);
	printf("tmp file: %s\n",tmp);
	cc->alg = alg;
	cc->filename = tmp;
	cc->hash_length = len;
      out:
	job->checksum_config = cc;
	return err;
}

void free_checksum(struct checksum_config *cc)
{
	free(cc);
}

void recv_msg(void *arg)
{
	int *sock_fd = (int *)arg;
	int len, i, maxlen = sizeof(struct callback);
	struct sockaddr_nl dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct msghdr msg;
	struct callback *cb;
	
	memset(&dest_addr, 0, sizeof(dest_addr));

	nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(maxlen));
	memset(nlh, 0, NLMSG_SPACE(maxlen));

	iov.iov_base = (void *) nlh;
	iov.iov_len = NLMSG_SPACE(sizeof(struct callback));
	msg.msg_name = (void *) &dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	len = recvmsg(*sock_fd, &msg, 0);
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

	close(*sock_fd);
	free(nlh);
}

void recv_signal(int sig, siginfo_t *info, void *context)
{
	printf("Signal received: %i\n", info->si_int);
	signal_recvd = 1;
}

int main(int argc, char *const argv[])
{
	struct job *job = NULL;
	int job_type, sock_fd, option = 0, err = 0, c, xpress = -1, xcrypt = -1, cl_netlink = -1, pid = 0, jobid = -1;
	struct sigaction sig;
	struct sockaddr_nl src_addr;
	pthread_t st = -1;
	char *input = NULL, *output = NULL, *alg = NULL, *password = NULL;
	int priority = -400;

   	
	option = getopt(argc, argv, "j:");
	if (option == 'j') {
		job_type = atoi(optarg);
		if (job_type == 0) {
			printf("wrong JOB ID.\n");
			exit(-1);
		}
	} else {
		printf("Error: Please give job type.\n");
		exit(-1);
	}

	job = malloc(sizeof(struct job));
	if (job == NULL) {
		printf("Error allocating memory to job\n");
		exit(-1);
	}
	job->type = job_type;

	switch (job_type) {
	case CHECKSUM:
		job->checksum_config = NULL;
		while ((c = getopt(argc, argv, "a:i:z:")) != -1) {
			switch (c) {
			case 'a':
				if (alg != NULL) {
					printf
					    ("Error: -a option is two times.\n");
					err = -1;
					goto out;
				}
				alg = argv[optind - 1];
				break;
			case 'i':
				if (input != NULL) {
					printf
					    ("Error: -i option is two times.\n");
					err = -1;
					goto out;
				}
				input = argv[optind - 1];
				break;
			case 'z':
				priority = atoi(argv[optind - 1]);
				break;
			case '?':
				printf
				    ("Error: Unrecognized options in arguments\n");
				err = -1;
				goto out;
			}
		}
		if (alg == NULL || input == NULL) {
			printf("Error: Input is missing.\n");
			err = -1;
			goto out;
		}
		if (alloc_checksum(job, alg, input) != 0)
			goto out;
		break;
	case CONCATENATE:
		job->concate_config = NULL;
		while ((c = getopt(argc, argv, "ci:o:")) != -1) {
			switch (c) {
			case 'i':
				if (input != NULL) {
					printf
					    ("Error: -i option is two times.\n");
					err = -1;
					goto out;
				}
				input = argv[optind - 1];
				break;
			case 'o':
				if (output != NULL) {
					printf
					    ("Error: -o option is two times.\n");
					err = -1;
					goto out;
				}
				output = argv[optind - 1];
				break;
			case '?':
				printf
				    ("Error: Unrecognized options in arguments\n");
				err = -1;
				goto out;
			}
		}
		if (input == NULL || output == NULL) {
			printf("Error: Input is missing.\n");
			err = -1;
			goto out;
		}
		if (create_concat_config(job, input, output) != 0)
			goto out;
		break;
	case XPRESS:
		job->xpress_config = NULL;
		while ((c = getopt(argc, argv, "a:cdi:o:ns")) != -1) {
			switch (c) {
			case 'a':
				if (alg != NULL) {
					printf
					    ("Error: -a option is more than once.\n");
					err = -1;
					goto out;
				}
				alg = argv[optind - 1];
				break;
			case 'c':
				if (xpress != -1) {
					printf
					    ("Error: only one of -c or -d can be specified.\n");
					err = -1;
					goto out;
				}
				xpress = 1;
				break;
			case 'd':
				if (xpress != -1) {
					printf
					    ("Error: only one of -c or -d can be specified.\n");
					err = -1;
					goto out;
				}
				xpress = 0;
				break;
			case 'i':
				if (input != NULL) {
					printf
					    ("Error: -i option is more than once.\n");
					err = -1;
					goto out;
				}
				input = argv[optind - 1];
				break;
			case 'o':
				if (output != NULL) {
					printf
					    ("Error: -o option is more than once.\n");
					err = -1;
					goto out;
				}
				output = argv[optind - 1];
				break;
			case 'n':
				if (cl_netlink != -1) {
					printf
					    ("Error: only one of -n or -s can be specified.\n");
					err = -1;
					goto out;
				}
				cl_netlink = 1;
				break;
			case 's':
				if (cl_netlink != -1) {
					printf
					    ("Error: only one of -n or -s can be specified.\n");
					err = -1;
					goto out;
				}
				cl_netlink = 0;
				break;
			case '?':
				printf
				    ("Error: Unrecognized options in arguments\n");
				err = -1;
				goto out;
			}
		}
		if (alg == NULL || input == NULL) {
			printf("Error: Input is missing.\n");
			err = -1;
			goto out;
		}
		if (xpress == -1) {
			printf
			    ("compression/decompression operation not specified\n");
			err = -1;
			goto out;
		}
		if (alloc_xpress
		    (job, alg, input, output, xpress, cl_netlink) != 0)
			goto out;
		break;
	case XCRYPT:
		job->xcrypt_config = NULL;
                while ((c = getopt(argc, argv, "c:p:edi:o:")) != -1) {
                        switch (c) {

                        case 'c':
                                if (alg != NULL) {
                                        printf
                                            ("Error: -c option is more than once.\n");
                                        err = -1;
                                        goto out;
                                }
                                alg = argv[optind - 1];
                                break;
			case 'p':
                                if (password != NULL) {
                                        printf
                                            ("Error: -i option is more than once.\n");
                                        err = -1;
                                        goto out;
                                }
                                password = argv[optind - 1];
                                break;
			case 'e':
                                if (xcrypt != -1) {
                                        printf
                                            ("Error: only one of -e or -d can be specified.\n");
                                        err = -1;
                                        goto out;
                                }
                                xcrypt = 1;
                                break;
                        case 'd':
                                if (xcrypt != -1) {
                                        printf
                                            ("Error: only one of -e or -d can be specified.\n");
                                        err = -1;
                                        goto out;
                                }
                                xcrypt = 0;
                                break;
                        case 'i':
                                if (input != NULL) {
                                        printf
                                            ("Error: -i option is more than once.\n");
                                        err = -1;
                                        goto out;
                                }
                                input = argv[optind - 1];
                                break;
                        case 'o':
                                if (output != NULL) {
                                        printf
                                            ("Error: -o option is more than once.\n");
                                        err = -1;
                                        goto out;
                                }
                                output = argv[optind - 1];
                                break;
			}
		}
		if (alg == NULL || password == NULL || input == NULL) {
                        printf("Error: Input is missing.\n");
                        err = -1;
                        goto out;
                }
                if (xcrypt == -1) {
                        printf
                            ("encrypt/decrypt operation not specified\n");
                        err = -1;
                        goto out;
                }
                if (alloc_xcrypt
                    (job, alg, password, input, output, xcrypt) != 0)
                        goto out;
                break;

		break;
	case LIST:
		break;
	case REMOVE:
		while ((c = getopt(argc, argv, "i:p:")) != -1) {
			switch (c) {
			case 'i':
				if (jobid != -1) {
					printf
					    ("Error: -i option is two times.\n");
					err = -1;
					goto out;
				}
				jobid = atoi(optarg);
				break;
			case 'p':
				if (pid != 0) {
					printf
					    ("Error: -p option is two times.\n");
					err = -1;
					goto out;
				}
				pid = atoi(optarg);
				break;
			case '?':
				printf
				    ("Error: Unrecognized options in arguments\n");
				err = -1;
				goto out;
			}
		}
		if (jobid == -1 || pid == 0) {
			printf("Error: Input is missing.\n");
			err = -1;
			goto out;
		}
		create_task_config(job, jobid, pid);
		break;
	case MODIFY:
		while ((c = getopt(argc, argv, "i:p:z:")) != -1) {
			switch (c) {
			case 'i':
				if (jobid != -1) {
					printf
					    ("Error: -i option is two times.\n");
					err = -1;
					goto out;
				}
				jobid = atoi(optarg);
				break;
			case 'p':
				if (pid != 0) {
					printf
					    ("Error: -p option is two times.\n");
					err = -1;
					goto out;
				}
				pid = atoi(optarg);
				break;
			case 'z':
				if (priority != -400) {
					printf
					    ("Error: -zoption is two times.\n");
					err = -1;
					goto out;
				}
				priority = atoi(optarg);
				break;
			case '?':
				printf
				    ("Error: Unrecognized options in arguments\n");
				err = -1;
				goto out;
			}
		}
		if (jobid == -1 || pid == 0) {
			printf("Error: Input is missing.\n");
			err = -1;
			goto out;
		}
		create_task_config(job, jobid, pid);
		break;

	default:
		goto out;
	}

	job->jobid = 1;
	job->pid = getpid();
	job->priority = priority;
	
	if ((job_type == CHECKSUM) || (job_type == XCRYPT) || (job_type == CONCATENATE) || (job_type == XPRESS)){
                sig.sa_sigaction = recv_signal;
                sig.sa_flags = SA_SIGINFO;
                sigaction(CALLBACK_SIG, &sig, NULL);

		if (cl_netlink != 0)
		{
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

			pthread_create(&st, NULL, (void *) &recv_msg, &sock_fd);
        	}
	}

	err = syscall(__NR_submitjob, job);
	if (err == 0)
		printf("syscall returned %d\n", err);
	else{
		perror("Result of submitjob syscall");
		goto out;
	}

	if (st != -1)
		pthread_join(st, NULL);
	else if (cl_netlink == 0){
		while (1){
			if (signal_recvd == 1)
				break;
			printf("Waiting for signal\n");
			sleep(1);
		}
	}

out:
	if (job_type == CONCATENATE) {
		if (job->concate_config != NULL)
			free_concat_config(job->concate_config);
	} else if (job_type == CHECKSUM) {
		if (job->checksum_config != NULL)
			free_checksum(job->checksum_config);
	} else if (job_type == XPRESS) {
		if (job->xpress_config != NULL)
			free_xpress(job->xpress_config);
	} 
	else if (job_type == XCRYPT) {
                if (job->xcrypt_config != NULL)
                        free_xcrypt(job->xcrypt_config);
        }else if (job_type == LIST) {
		printf("JOBID|PID|PRIORITY\n");
		printf("%s\n", job->task_config.buf);

	}

	free(job);
	return err;
}
