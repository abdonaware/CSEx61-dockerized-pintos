#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler(struct intr_frame *f UNUSED);
static void get_args(struct intr_frame *f, int *args, int num);

/* Checks if the user address is valid */
bool valid(void *vaddr);
/* Calls exit with -1 status */
void kill(void);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f UNUSED)
{
  if (!valid(f->esp))
  {
    kill();
  }

  int syscall_number = *(int *)f->esp;
  int *arg = (int *)f->esp;

  switch (syscall_number)
  {

  case SYS_HALT:
    break;

  case SYS_EXIT:
    int status = arg[1];
    break;

  case SYS_EXEC:
    char *cmdline = (char *)arg[1];
    break;

  case SYS_WAIT:
    int pid = arg[1];
    break;

  case SYS_CREATE:
    char *file = (char *)arg[1];
    unsigned initial_size = arg[2];
    break;

  case SYS_REMOVE:
    char *file = (char *)arg[1];
    break;

  case SYS_OPEN:
    char *file = (char *)arg[1];
    break;

  case SYS_FILESIZE:
    int fd = arg[1];
    break;

  case SYS_READ:
    int fd = arg[1];
    void *buffer = (void *)arg[2];
    unsigned size = arg[3];
    break;

  case SYS_WRITE:
    int fd = arg[1];
    void *buffer = (void *)arg[2];
    unsigned size = arg[3];
    break;

  case SYS_SEEK:
    int fd = arg[1];
    unsigned position = arg[2];
    break;

  case SYS_TELL:
    int fd = arg[1];
    break;

  case SYS_CLOSE:
    int fd = arg[1];
    break;

  default:
    printf("Unknown system call number: %d\n", syscall_number);
    thread_exit();
  }
}

// SYS_HALT,                   /* Halt the operating system. */
//     SYS_EXIT,                   /* Terminate this process. */
//     SYS_EXEC,                   /* Start another process. */
//     SYS_WAIT,                   /* Wait for a child process to die. */
//     SYS_CREATE,                 /* Create a file. */
//     SYS_REMOVE,                 /* Delete a file. */
//     SYS_OPEN,                   /* Open a file. */
//     SYS_FILESIZE,               /* Obtain a file's size. */
//     SYS_READ,                   /* Read from a file. */
//     SYS_WRITE,                  /* Write to a file. */
//     SYS_SEEK,                   /* Change position in a file. */
//     SYS_TELL,                   /* Report current position in a file. */
//     SYS_CLOSE,                  /* Close a file. */

bool valid(void *vaddr)
{
  return (is_user_vaddr(vaddr) &&
          pagedir_get_page(thread_current()->pagedir, vaddr) != NULL);
}
void kill(void)
{
  exit(-1);
}