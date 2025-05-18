#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;

void syscall_init (void);
struct file *open_with_locks(const char *file);
#endif /* userprog/syscall.h */
