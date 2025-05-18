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
#include "userprog/process.h"

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
tid_t exec(const char *cmd_line);
int exit_process(int status);
void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_mutex);
}

static void syscall_handler(struct intr_frame *f UNUSED)
{

  int args[3];
  if (!valid(f->esp))
  {
    kill();
  }

  int syscall_number = *(int *)f->esp;
  (int *)f->esp;

  switch (syscall_number)
  {

  case SYS_HALT:
  {
    shutdown_power_off();
    break;
  }

  case SYS_EXIT:
  {
    get_args(f, args, 1);
    int status = args[0];
    if (!valid(status))
    {
      kill();
    }
    exit(status);
    break;
  }

  case SYS_EXEC:
  {
    get_args(f, args, 1);
    char *cmdline = (char *)args[0];
    if (!valid(cmdline))
    {
      kill();
    }
    f->eax = exec(cmdline);
    break;
  }

  case SYS_WAIT:
  {
    get_args(f, args, 1);
    int pid = args[0];
    f->eax = process_wait(pid);
    break;
  }

  case SYS_CREATE:
  {
    get_args(f, args, 2);
    char *file = (char *)args[0];
    unsigned initial_size = (unsigned)args[1];
    if (!valid(file))
    {
      kill();
    }
    f->eax = create(file, initial_size);
    break;
  }

  case SYS_REMOVE:
  {
    get_args(f, args, 1);
    char *file = (char *)args[0];
    if (!valid(file))
    {
      kill();
    }
    f->eax = remove(file);
    break;
  }

  case SYS_OPEN:
  {
    get_args(f, args, 1);
    char *file = (char *)args[0];
    if (!valid(file))
    {
      kill();
    }
    f->eax = open(file);
    break;
  }

  case SYS_FILESIZE:
  {
    get_args(f, args, 1);
    int fd = args[0];
    if (!valid(fd))
    {
      kill();
    }
    f->eax = get_file_size(fd);
    break;
  }

  case SYS_READ:
  {
    get_args(f, args, 3);
    int fd = args[0];
    void *buffer = (void *)args[1];
    unsigned size = (unsigned)args[2];
    if (!valid(buffer))
    {
      kill();
    }
    if (!valid(buffer + size))
    {
      kill();
    }
    if (!valid(buffer + size - 1))
    {
      kill();
    }
    f->eax = read(fd, buffer, size);
    break;
  }

  case SYS_WRITE:
  {
    get_args(f, args, 3);
    int fd = args[0];
    void *buffer = (void *)args[1];
    unsigned size = (unsigned)args[2];
    if (!valid(buffer))
    {
      kill();
    }
    if (!valid(buffer + size))
    {
      kill();
    }
    if (!valid(buffer + size - 1))
    {
      kill();
    }
    f->eax = write(fd, buffer, size);
    break;
  }

  case SYS_SEEK:
  {
    get_args(f, args, 2);
    int fd = args[0];
    unsigned position = args[1];
    if (!valid(position))
    {
      kill();
    }
    if (!valid(position + 1))
    {
      kill();
    }
    if (!valid(position - 1))
    {
      kill();
    }
    seek(fd, position);
    break;
  }

  case SYS_TELL:
  {
    get_args(f, args, 1);
    int fd = args[0];
    if (!valid(fd))
    {
      kill();
    }
    f->eax = tell(fd);
    break;
  }

  case SYS_CLOSE:
  {
    get_args(f, args, 1);
    int fd = args[0];
    if (!valid(fd))
    {
      kill();
    }
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
  exit_process(-1);
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
  curr_th->next_fd++;

  list_push_back(&curr_th->file_list, &curr_fd->elem);
  return curr_fd->fd;
}

int get_file_size(int fd)
{
  struct thread *curr_th = thread_current();
  struct list_elem *e;
  struct file_descriptor *curr_fd;

  for (e = list_begin(&curr_th->file_list); e != list_end(&curr_th->file_list); e = list_next(e))
  {
    curr_fd = list_entry(e, struct file_descriptor, elem);
    if (curr_fd->fd == fd)
    {
      return file_length(curr_fd->file_ptr);
    }
  }
  return -1; // File descriptor not found
}

int read(int fd, void *buffer, unsigned size)
{
  lock_acquire(&file_mutex);

  struct thread *curr_th = thread_current();
  struct list_elem *e;
  struct file_descriptor *curr_fd;
  if (fd == 0)
  {
    // Read from stdin
    int bytes_read = input_getc(buffer, size);
    lock_release(&file_mutex);
    return bytes_read;
  }

  for (e = list_begin(&curr_th->file_list); e != list_end(&curr_th->file_list); e = list_next(e))
  {
    curr_fd = list_entry(e, struct file_descriptor, elem);
    if (curr_fd->fd == fd)
    {
      int bytes_read = file_read(curr_fd->file_ptr, buffer, size);
      lock_release(&file_mutex);
      return bytes_read;
    }
  }

  lock_release(&file_mutex);
  return -1; // File descriptor not found
}

int write(int fd, const void *buffer, unsigned size)
{
  lock_acquire(&file_mutex);

  struct thread *curr_th = thread_current();
  struct list_elem *e;
  struct file_descriptor *curr_fd;
  if (fd == 1)
  {
    putbuf(buffer, size);
  }

  for (e = list_begin(&curr_th->file_list); e != list_end(&curr_th->file_list); e = list_next(e))
  {
    curr_fd = list_entry(e, struct file_descriptor, elem);
    if (curr_fd->fd == fd)
    {
      int bytes_written = file_write(curr_fd->file_ptr, buffer, size);
      lock_release(&file_mutex);
      return bytes_written;
    }
  }

  lock_release(&file_mutex);
  return -1; // File descriptor not found
}
void seek(int fd, unsigned position)
{
  lock_acquire(&file_mutex);

  struct thread *curr_th = thread_current();
  struct list_elem *e;
  struct file_descriptor *curr_fd;

  for (e = list_begin(&curr_th->file_list); e != list_end(&curr_th->file_list); e = list_next(e))
  {
    curr_fd = list_entry(e, struct file_descriptor, elem);
    if (curr_fd->fd == fd)
    {
      file_seek(curr_fd->file_ptr, position);
      lock_release(&file_mutex);
      return;
    }
  }

  lock_release(&file_mutex);
}
unsigned tell(int fd)
{
  lock_acquire(&file_mutex);

  struct thread *curr_th = thread_current();
  struct list_elem *e;
  struct file_descriptor *curr_fd;

  for (e = list_begin(&curr_th->file_list); e != list_end(&curr_th->file_list); e = list_next(e))
  {
    curr_fd = list_entry(e, struct file_descriptor, elem);
    if (curr_fd->fd == fd)
    {
      unsigned position = file_tell(curr_fd->file_ptr);
      lock_release(&file_mutex);
      return position;
    }
  }

  lock_release(&file_mutex);
  return -1; // File descriptor not found
}
void close(int fd)
{
  lock_acquire(&file_mutex);

  struct thread *curr_th = thread_current();
  struct list_elem *e;
  struct file_descriptor *curr_fd;

  for (e = list_begin(&curr_th->file_list); e != list_end(&curr_th->file_list); e = list_next(e))
  {
    curr_fd = list_entry(e, struct file_descriptor, elem);
    if (curr_fd->fd == fd)
    {
      file_close(curr_fd->file_ptr);
      list_remove(e);
      free(curr_fd);
      lock_release(&file_mutex);
      return;
    }
  }

  lock_release(&file_mutex);
}
tid_t exec(const char *cmd_line)
{
  lock_acquire(&file_mutex);

  tid_t pid = process_execute(cmd_line);
  if (pid == TID_ERROR)
  {
    lock_release(&file_mutex);
    return -1; // Failed to execute
  }
  lock_release(&file_mutex);

  return pid;
}
int exit_process(int status)
{
  thread_current()->exit_status = status;
  process_exit();

  return status;
}