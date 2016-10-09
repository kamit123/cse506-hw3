#ifndef _UTIL_H
#define _UTIL_H

#include "job.h"

#define MAX_JOB 10

struct work {
    struct job *data;
    struct work *next;
};

extern struct xpress_config *alloc_xpress (struct xpress_config __user *xpress_config);
extern int xpress(struct job *job);
extern void dalloc_xpress (struct job *job);

extern struct concate_config *alloc_concat (struct concate_config __user *concate_config);
extern int concat(struct job *job);
extern void dalloc_concat (struct job *job);

extern struct checksum_config *alloc_checksum (struct checksum_config __user *checksum_Config);
extern int checksum(struct job *job);
extern void dalloc_checksum (struct job *job);

extern struct xcrypt_config *alloc_xcrypt (struct xcrypt_config __user *xcrypt_config);
extern int xcrypt(struct job *job);
extern void dalloc_xcrypt(struct job *job);

extern char *copy_string_from_usr(char *usrStr);

extern char *get_outfilename(char *infile, char *outfile, int flags);
extern char *get_tempfilename(char *filename);
extern void process_outfile(struct file *inf, struct file *temp_outf, char *outf_name, int flags);

extern int rename(struct file *old, struct file *new);
extern int unlink(struct file *victim);

extern int callback_socket(int pid, struct callback cb);
extern int signal(int pid, int data);
#endif
