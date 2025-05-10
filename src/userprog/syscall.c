#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler(struct intr_frame *f UNUSED);
static void get_args(struct intr_frame *f, int *args, int num);
struct lock file_mutex;

/* Checks if the user address is valid */
bool valid(void *vaddr);
/* Calls exit with -1 status */
void kill(void);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int get_file_size(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_mutex);
}

static void syscall_handler(struct intr_frame *f UNUSED)
{
  printf("Enter system call \n\n\n\n");
  int args[3];
  if (!valid(f->esp))
  {
    kill();
  }

  int syscall_number = *(int *)f->esp;
  int *arg = (int *)f->esp;

  printf("Before switch \n\n\n\n");

  switch (syscall_number)
  {

  case SYS_HALT:
  {
    shutdown_power_off();
    break;
  }

  case SYS_EXIT:
  {
    int status = arg[1];
    if (!valid((void *)status))
      kill();
    printf("%s: exit(%d)\n", thread_current()->name, status);
    exit(status);
    break;
  }

  case SYS_EXEC:
  {
    // char *cmdline = (char *)arg[1];
    // if (!valid(cmdline))
    //   exit(-1);

    // pid_t pid = exec(cmdline);
    // f->eax = pid;
    break;
  }

  case SYS_WAIT:
  {
    int pid = arg[1];
    break;
  }

  case SYS_CREATE:
  {
    get_args(f, args, 2);
    char *file = (char *)args[0];
    unsigned initial_size = (unsigned)args[1];
    f->eax = create(file, initial_size);
    break;
  }

  case SYS_REMOVE:
  {
    get_args(f, args, 1);
    char *file = (char *)args[0];
    f->eax = remove(file);
    break;
  }

  case SYS_OPEN:
  {
    get_args(f, args, 1);
    char *file = (char *)args[0];
    f->eax = open(file);
    break;
  }

  case SYS_FILESIZE:
  {
    int fd = arg[1];
    f->eax = get_file_size(fd);
    break;
  }

  case SYS_READ:
  {
    int fd = arg[1];
    void *buffer = (void *)arg[2];
    unsigned size = arg[3];
    // if (!valid(buffer))
    //   exit(-1);
    // if (!valid(buffer + size))
    //   exit(-1);
    // if (!valid(buffer + size - 1))
    //   exit(-1);
    f->eax = read(fd, buffer, size);
    break;
  }

  case SYS_WRITE:
  {
    int fd = arg[1];
    void *buffer = (void *)arg[2];
    unsigned size = arg[3];
    f->eax = write(fd, buffer, size);
    break;
  }

  case SYS_SEEK:
  {
    int fd = arg[1];
    unsigned position = arg[2];
    seek(fd, position);
    break;
  }

  case SYS_TELL:
  {
    int fd = arg[1];
    f->eax = tell(fd);
    break;
  }

  case SYS_CLOSE:
  {
    int fd = arg[1];
    close(fd);
    break;
  }

  default:
  {
    printf("Unknown system call number: %d\n", syscall_number);
    thread_exit();
  }
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
static void get_args(struct intr_frame *f, int *args, int num)
{
  for (int i = 0; i < num; i++)
  {
    void *ptr = f->esp + 4 + i * 4;
    if (!valid(ptr))
      kill();
    args[i] = *(int *)ptr;
  }
}
bool valid(void *vaddr)
{
  return (vaddr != NULL && is_user_vaddr(vaddr) &&
          pagedir_get_page(thread_current()->pagedir, vaddr) != NULL);
}
void kill(void)
{
  thread_exit();
}

bool create(const char *file, unsigned initial_size)
{

  lock_acquire(&file_mutex);

  bool successful = filesys_create(file, initial_size);

  lock_release(&file_mutex);

  return successful;
}

bool remove(const char *file)
{
  lock_acquire(&file_mutex);

  bool successful = filesys_remove(file);

  lock_release(&file_mutex);

  return successful;
}

int open(const char *file)
{
  lock_acquire(&file_mutex);

  struct file *f = filesys_open(file);

  lock_release(&file_mutex);

  if (f == NULL)
  {
    return -1; // file could not be opened
  }

  struct thread *curr_th = thread_current();
  struct file_descriptor *curr_fd = malloc(sizeof(struct file_descriptor));

  if (curr_fd == NULL)
  {
    return -1; // couldn't allocate
  }

  curr_fd->file_ptr = f;
  curr_fd->fd = curr_th->next_fd;
  lock_init(&curr_fd->read_write_lock);
  curr_th->next_fd++;

  list_push_back(&curr_th->file_list, &curr_fd->elem);
  return curr_fd->fd;
}
void exit(int status)
{
  struct thread *cur = thread_current();
  cur->exit_status = status; // Save the exit status, so that parent has access to it
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit(); // Clean up and terminate
}
int get_file_size(int fd)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct file_descriptor *fd_elem;

  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
  {
    fd_elem = list_entry(e, struct file_descriptor, elem);
    if (fd_elem->fd == fd)
    {
      return file_length(fd_elem->file_ptr);
    }
  }
  return -1; // File descriptor not found
}
int read(int fd, void *buffer, unsigned size)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct file_descriptor *fd_elem;

  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
  {
    fd_elem = list_entry(e, struct file_descriptor, elem);
    // Acquire the lock before reading
    if (fd_elem->fd == fd)
    {
      lock_acquire(&fd_elem->read_write_lock);
      int read_size = file_read(fd_elem->file_ptr, buffer, size);
      lock_release(&fd_elem->read_write_lock);
      return read_size;
    }
  }
  return -1; // File descriptor not found
}
int write(int fd, const void *buffer, unsigned size)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct file_descriptor *fd_elem;

  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
  {
    fd_elem = list_entry(e, struct file_descriptor, elem);
    if (fd_elem->fd == fd)
    {
      lock_acquire(&fd_elem->read_write_lock);
      int write_size = file_read(fd_elem->file_ptr, buffer, size);
      lock_release(&fd_elem->read_write_lock);
      return write_size;
    }
  }
  return -1; // File descriptor not found
}
void seek(int fd, unsigned position)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct file_descriptor *fd_elem;

  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
  {
    fd_elem = list_entry(e, struct file_descriptor, elem);
    if (fd_elem->fd == fd)
    {
      file_seek(fd_elem->file_ptr, position);
      return;
    }
  }
}
unsigned tell(int fd)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct file_descriptor *fd_elem;

  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
  {
    fd_elem = list_entry(e, struct file_descriptor, elem);
    if (fd_elem->fd == fd)
    {
      return file_tell(fd_elem->file_ptr);
    }
  }
  return -1; // File descriptor not found
}
void close(int fd)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct file_descriptor *fd_elem;

  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
  {
    fd_elem = list_entry(e, struct file_descriptor, elem);
    if (fd_elem->fd == fd)
    {
      file_close(fd_elem->file_ptr);
      list_remove(&fd_elem->elem);
      free(fd_elem);
      return;
    }
  }
}

// pid_t exec(const char *cmd_line)
// {

// }