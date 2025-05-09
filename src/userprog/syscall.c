#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"


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

  int fd;
  int status;
  char *cmdline;
  int pid;
  char *file;
  unsigned initial_size;
  void *buffer;
  unsigned size;
  unsigned position;

  switch (syscall_number)
  {
  case SYS_HALT:
    // implement halt
    break;

  case SYS_EXIT:
    status = arg[1];
    // implement exit with status
    break;

  case SYS_EXEC:
    cmdline = (char *)arg[1];
    if (!valid(cmdline)) exit(-1);

    pid_t pid = exec(cmdline);
    f->eax = pid;
    break;

  case SYS_WAIT:
    pid = arg[1];
    // implement wait with pid
    break;

  case SYS_CREATE:
    file = (char *)arg[1];
    initial_size = arg[2];
    // implement create
    break;

  case SYS_REMOVE:
    file = (char *)arg[1];
    // implement remove
    break;

  case SYS_OPEN:
    file = (char *)arg[1];
    // implement open
    break;

  case SYS_FILESIZE:
    fd = arg[1];
    // implement filesize
    break;

  case SYS_READ:
    fd = arg[1];
    buffer = (void *)arg[2];
    size = arg[3];
    // implement read
    break;

  case SYS_WRITE:
    fd = arg[1];
    buffer = (void *)arg[2];
    size = arg[3];
    // implement write
    break;

  case SYS_SEEK:
    fd = arg[1];
    position = arg[2];
    // implement seek
    break;

  case SYS_TELL:
    fd = arg[1];
    // implement tell
    break;

  case SYS_CLOSE:
    fd = arg[1];
    // implement close
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
  //exit(-1);
  /*Not implemented*/
}

void exit(int status) {
    struct thread *cur = thread_current();
    cur->exit_status = status;  // Save the exit status, so that parent has access to it
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();  // Clean up and terminate
}


pid_t exec (const char *cmd_line) {
    
}