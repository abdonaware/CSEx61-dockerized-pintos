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
#include "string.h"

static void syscall_handler(struct intr_frame *f UNUSED);
static void get_args(struct intr_frame *f, int *args, int num);
struct lock file_mutex;

/* Checks if the user address is valid */
bool valid(void *vaddr);
/* Calls exit with -1 status */
void kill(void);
pid_t exec(const char *cmd_line);
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
  
  int args[3];
  if (!valid(f->esp))
  {
    kill();
  }

  int syscall_number = *(int *)f->esp;
  int *arg = (int *)f->esp;

 

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
    get_args(f, args, 1);
     
    // printf("aaaaaaaaaaaaaa %d\n", status);
    exit(status);
    break;
  }

  case SYS_EXEC:
  {
    get_args(f, args, 1);
    char *cmdline = (char *)args[0];
  
    if (!valid(cmdline))
      exit(-1);
    
    // Exec with full cmdline
    char *k_cmdline = palloc_get_page(0);
    if (k_cmdline == NULL)
      exit(-1);
    strlcpy(k_cmdline, cmdline, PGSIZE);
  
    pid_t pid = exec(k_cmdline);
    f->eax = pid;
  
    palloc_free_page(k_cmdline);
    break;
  }
  
  


  case SYS_WAIT:
  {
    get_args(f, args, 1);
    int pid = arg[1];
    f->eax = process_wait(pid);
    // printf("aaaaaaaaaaaaaa %d\n", pid);
    break;
  }

  case SYS_CREATE:
  {
    get_args(f, args, 2);
    char *file = (char *)args[0];
    unsigned initial_size = (unsigned)args[1];
    if (!valid(file))
      exit(-1);
    if (!valid(file + initial_size))
      exit(-1);
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
    if (!valid(file))
      exit(-1);
    f->eax = open(file);
    break;
  }

  case SYS_FILESIZE:
  {
    get_args(f, args, 1);
    int fd = arg[1];
    f->eax = get_file_size(fd);
    break;
  }

  case SYS_READ:
  {
    get_args(f, args, 3);
    int fd = arg[1];
    void *buffer = (void *)arg[2];
    unsigned size = arg[3];
    if (!valid(buffer))
      exit(-1);
    if (!valid(buffer + size))
      exit(-1);
    if (!valid(buffer + size - 1))
      exit(-1);
    f->eax = read(fd, buffer, size);
    break;
  }

  case SYS_WRITE:
  {
    get_args(f, args, 3);
    int fd = arg[1];
    void *buffer = (void *)arg[2];
    unsigned size = arg[3];
    if (!valid(buffer))
      exit(-1);
    if (!valid(buffer + size))
      exit(-1);
    if (!valid(buffer + size - 1))
      exit(-1);

    f->eax = write(fd, buffer, size);
    break;
  }

  case SYS_SEEK:
  {
    get_args(f, args, 2);
    int fd = arg[1];
    unsigned position = arg[2];
    seek(fd, position);
    break;
  }

  case SYS_TELL:
  {
    get_args(f, args, 1);
    int fd = arg[1];
    f->eax = tell(fd);
    break;
  }

  case SYS_CLOSE:
  {
    get_args(f, args, 1);
    int fd = arg[1];
    close(fd);
    break;
  }

  default:
  {
    printf("Unknown system call number: %d\n", syscall_number);
    exit(-1);
  }
  }
}

static void get_args(struct intr_frame *f, int *args, int num)
{
  for (int i = 0; i < num; i++)
  {
    void *ptr = f->esp + 4 + i * 4;
    if (!valid(ptr))
      {
      exit(-1);
    }
    args[i] = *(int *)ptr;
  }
}

pid_t exec(const char *cmd_line) {
  
  tid_t tid = process_execute(cmd_line);

  if (tid == TID_ERROR) {
      return -1;
  }  

  return tid;
}


bool valid(void *vaddr)
{
  return (vaddr != NULL && is_user_vaddr(vaddr) &&
          pagedir_get_page(thread_current()->pagedir, vaddr) != NULL);
}
void kill(void)
{
  exit(-1);
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

  
  if (f == NULL){
    lock_release(&file_mutex);
    return -1;
  }
  
  
  struct thread *curr_th = thread_current();
  struct file_descriptor *curr_fd = palloc_get_page(sizeof(struct file_descriptor));
  if (curr_fd == NULL){
    lock_release(&file_mutex);
    return -1;
  }

  strlcpy(curr_fd->filename, file, sizeof(curr_fd->filename));

  curr_fd->file_ptr = f;
  curr_fd->fd = curr_th->next_fd++;
  //sema_init(&curr_fd->read_write_sema, 1);
  curr_fd->executing = false;
  
  list_push_back(&curr_th->file_list, &curr_fd->elem);
  lock_release(&file_mutex);

  return curr_fd->fd;
}
int open_file_with_lock(const char *file)
{
  lock_acquire(&file_mutex);
  struct file *f = filesys_open(file);
  if (f == NULL)
  {
    lock_release(&file_mutex);
    return -1;
  }
  lock_release(&file_mutex);
  return f;
}


void exit(int status)
{
  struct thread *cur = thread_current();
  cur->exit_status = status; // Save the exit status, so that parent has access to it
  // if (cur->executing_file != NULL) {
  //   file_allow_write(cur->executing_file);
  //   file_close(cur->executing_file);
  //   cur->executing_file = NULL;
  // }
  // printf("%s: exit(%d)\n", cur->name, status);

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

    if (fd == 0)
    {
      uint8_t *buf = buffer;
      for (unsigned i = 0; i < size; i++)
        buf[i] = input_getc();
      return size;
    }

    for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
    {
      fd_elem = list_entry(e, struct file_descriptor, elem);
      if (fd_elem->fd == fd)
      {
        lock_acquire(&file_mutex);
        int read_size = file_read(fd_elem->file_ptr, buffer, size);
        lock_release(&file_mutex);

        return read_size;
      }
    }
    return -1;
  }

  int write(int fd, const void *buffer, unsigned size)
  {
    struct thread *cur = thread_current();
    struct list_elem *e;
    struct file_descriptor *fd_elem;

    if (fd == 1)
    {
      putbuf(buffer, size);
      return size;
    }

    for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list); e = list_next(e))
    {
      fd_elem = list_entry(e, struct file_descriptor, elem);
      if (fd_elem->fd == fd)
      {
        lock_acquire(&file_mutex);
        int write_size = file_write(fd_elem->file_ptr, buffer, size);
        lock_release(&file_mutex);

        return write_size;
      }
    }
    return -1;
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
      palloc_free_page(fd_elem);
      return;
    }
  }
}