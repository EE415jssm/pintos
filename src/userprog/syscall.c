#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
bool create(const char* file, unsigned initial_size);
bool remove (const char* file);
unsigned wait(tid_t tid);

void check_address(void* address) {
  if (!is_user_vaddr(address)) exit(-1);
}

void get_argument(void * esp, int * arg, int count) {
  int i;
  for (i = 1; i <= count; i++) {
    check_address (esp + 4 * i);
    *(arg + 4 * (i - 1)) = *((int**)(esp + 4 * i));
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int * arg;
  int syscall;

  syscall = *((int *)(f->esp));

  switch(syscall) {
  case (SYS_HALT):
    halt();
    break;
  case (SYS_EXIT):
    get_argument(f->esp, arg, 1);
    exit(*arg);
    break;
  case (SYS_EXEC):
    get_argument(f->esp, arg, 1);
    check_address((char *)*arg);
    f->eax = exec((char *)*arg);
    break;
  case (SYS_WAIT):
    get_argument(f->esp, arg, 1);
    f->eax = wait((int)*arg);
    break;
  case (SYS_CREATE):
    get_argument(f->esp, arg, 2);
    check_address((char *)*arg);
    f->eax = create((char *)*arg, (unsigned)*(arg + 4));
    break;
  case (SYS_REMOVE):
    get_argument(f->esp, arg, 1);
    check_address((char *)*arg);
    f->eax = remove((char *)*arg);
    break;
  case (SYS_OPEN):
    get_argument(f->esp, arg, 1);
    check_address((char *)*arg);
    f->eax = open((char *)*arg);
    break;
  case (SYS_FILESIZE):
    get_argument(f->esp, arg, 1);
    f->eax = filesize(*arg);
    break;
  case (SYS_READ):
    get_argument(f->esp, arg, 3);
    check_address((void *)*(arg + 4));
    f->eax = read(*arg, (void *)*(arg + 4), (unsigned)*(arg + 8));
    break;
  case (SYS_WRITE):
    get_argument(f->esp, arg, 3);
    check_address((void *)*(arg + 4));
    f->eax = write(*arg, (void *)*(arg + 4), (unsigned)*(arg + 8));
    break;
  case (SYS_SEEK):
    get_argument(f->esp, arg, 2);
    seek(*arg, (unsigned)*(arg + 4));
    break;
  case (SYS_TELL):
    get_argument(f->esp, arg, 1);
    f->eax = tell(*arg);
    break;
  case (SYS_CLOSE):
    get_argument(f->esp, arg, 1);
    close(*arg);
    break;
  default:
    thread_exit ();
  }
}

void halt(void) {
  shutdown_power_off();
}

void exit(int status) {
  thread_current()->is_process_exit = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

bool create(const char* file, unsigned initial_size) {
  return (filesys_create(file, initial_size));
}

bool remove(const char* file) {
  return (filesys_remove(file));
}

int open(const char *file){
  return process_add_file(filesys_open(file));
}
int filesize(int fd){
  struct file *f= process_get_file(fd);
  if(f==NULL){
    return -1;
  }
  return (int)file_length(f);

}
int read(int fd, void *buffer, unsigned size){
  lock_acquire(&filesys_lock);
  if(fd==0){
    unsigned i=0;
    while((i++)<size){
      *(char *)(buffer + i) = input_getc();
    }
    lock_release(&filesys_lock);
    return size;
  }
  else{
    struct file *f = process_get_file(fd);
    if(f==NULL){
      lock_release(&filesys_lock);
      return -1;
    }
    size = file_read(f, buffer, size);
    lock_release(&filesys_lock);
    return size;
  } 
}
int write(int fd, const void *buffer, unsigned size){
  lock_acquire(&filesys_lock);
  if(fd==1){
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return size;
  }
  else{
    struct file *f = process_get_file(fd);
    if(f==NULL){
      lock_release(&filesys_lock);
      return 0;
    }
    lock_release(&filesys_lock);
    size = file_write(f, buffer, size);
    return size;
  }
}
void seek(int fd, unsigned position){
  struct file * f = process_get_file(fd);
  if(f==NULL){
    return;
  }
  file_seek(f,position);
}
int tell(int fd){
  struct file * f = process_get_file(fd);
  if(f==NULL){
    return -1;
  }
  return file_tell(f);
}
void close(int fd){
  struct file * f = process_get_file(fd);
  if(f==NULL){
    return;
  }
  process_close_file(fd);
}

tid_t exec(const *file_name) {
  int child_pid;
  child_pid = process_execute(file_name);
  struct thread* child = get_child_process(child_pid);
  sema_down(&child->load_sema);
  if (child->is_loaded == -1) return -1;
  return child_pid;
}

unsigned wait(tid_t tid) {
  return (process_wait(tid));
}
