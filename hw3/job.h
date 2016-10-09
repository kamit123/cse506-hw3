#ifndef _JOB_H
#define _JOB_H

#define __NR_submitjob 359
#define SOCKET_PROTOCOL NETLINK_USERSOCK
#define CALLBACK_SIG 44
#define COMPRESS 1
#define DECOMPRESS 2
#define ENCRYPT 1
#define DECRYPT 2
#define RENAME 4
#define REWRITE 8
#define MAX_BUFFER_LENGTH 4096
#define CALLBACK_SOCKET 1
#define CALLBACK_SIGNAL 2

enum jobtype {
	XCRYPT = 1,
	XPRESS,
	CHECKSUM,
	CONCATENATE,
	LIST,
	REMOVE,
	MODIFY
};

struct xcrypt_config {
	char *infile;
        char *outfile;
        char *cipher;
        unsigned char *keybuf;
        int keylen;
        int flags;
};

struct concate_config {
	char **infile;
	char *outfile;
	int flag;
};

struct checksum_config {
	char *filename;
	char *alg;
	unsigned int hash_length;
	int flag;
};

struct xpress_config {
	char *alg;
	char *infile;
	char *outfile;
	int flags;
};

struct task_config {
	int jobid;	
	int pid;
	char buf[MAX_BUFFER_LENGTH];
};

struct job {
	int jobid;
	int pid;
	int priority;
	enum jobtype type;
	union {
		struct xcrypt_config *xcrypt_config;
		struct xpress_config *xpress_config;
		struct checksum_config *checksum_config;
		struct concate_config *concate_config;
		struct task_config task_config;
	};
	int callback_opt;
	int flags;
};

struct callback {
        int jobid;
        int result;
        unsigned char msg[20];
        int msglen;
};

#endif
