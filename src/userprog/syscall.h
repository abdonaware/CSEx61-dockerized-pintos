#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;

void syscall_init (void);
int open_file_with_lock(const char *file);
#endif /* userprog/syscall.h */
