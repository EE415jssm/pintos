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
/*This function checks the validity of address. If it is not valid,
call exit(-1) */
void check_address(void* address) {
  if (!is_user_vaddr(address)) exit(-1);
}

/* This function gets argument from stack in the range of esp
to esp+4*count*/
void get_argument(void * esp, int * arg, int count) {
  int i;
  for (i = 1; i <= count; i++) {
    check_address (esp + 4 * i);
    *(arg + 4 * (i - 1)) = *((int**)(esp + 4 * i));
  }
}
/*This function initializes the system call. Especially, this also
initilizes filesys_lock */

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}
/* This function makes system call functions with switch. This puts
the arguments into each function. What function to call is determined
by esp value. */
static void
syscall_handler (struct intr_frame *f) 
{
  int * arg = (void *)malloc(4*sizeof(void *));
  int syscall;

  syscall = *((int *)(f->esp));

  switch(syscall) {
  case (SYS_HALT):
    halt();
    free(arg);
    break;
  case (SYS_EXIT):
    get_argument(f->esp, arg, 1);
    exit(*arg);
    break;
  case (SYS_EXEC):
    get_argument(f->esp, arg, 1);
    check_address((char *)*arg);
    f->eax = exec((char *)*arg);
    free(arg);
    break;
  case (SYS_WAIT):
    get_argument(f->esp, arg, 1);
    f->eax = wait((int)*arg);
    free(arg);
    break;
  case (SYS_CREATE):
    get_argument(f->esp, arg, 2);
    check_address((char *)*arg);
    f->eax = create((char *)*arg, (unsigned)*(arg + 4));
    free(arg);
    break;
  case (SYS_REMOVE):
    get_argument(f->esp, arg, 1);
    check_address((char *)*arg);
    f->eax = remove((char *)*arg);
    free(arg);
    break;
  case (SYS_OPEN):
    get_argument(f->esp, arg, 1);
    check_address((char *)*arg);
    f->eax = open((char *)*arg);
    free(arg);
    break;
  case (SYS_FILESIZE):
    get_argument(f->esp, arg, 1);
    f->eax = filesize(*arg);
    free(arg);
    break;
  case (SYS_READ):
    get_argument(f->esp, arg, 3);
    check_address((void *)*(arg + 4));
    f->eax = read(*arg, (void *)*(arg + 4), (unsigned)*(arg + 8));
    free(arg);
    break;
  case (SYS_WRITE):
    get_argument(f->esp, arg, 3);
    check_address((void *)*(arg + 4));
    f->eax = write(*arg, (void *)*(arg + 4), (unsigned)*(arg + 8));
    free(arg);
    break;
  case (SYS_SEEK):
    get_argument(f->esp, arg, 2);
    seek(*arg, (unsigned)*(arg + 4));
    free(arg);
    break;
  case (SYS_TELL):
    get_argument(f->esp, arg, 1);
    f->eax = tell(*arg);
    free(arg);
    break;
  case (SYS_CLOSE):
    get_argument(f->esp, arg, 1);
    close(*arg);
    free(arg);
    break;
  default:
    thread_exit ();
  }
}
/* This function shutdowns pintos */
void halt(void) {
  shutdown_power_off();
}
/* This function exits the process. This prints out the message that
"Process Name : exit(status)"*/
void exit(int status) {
  thread_current()->is_process_exit = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}


/* This function creates file which has the size of initial_size.
Returns true if it is succeeded or false if it is not succeeded.*/
bool create(const char* file, unsigned initial_size) {
  if (file == NULL) exit(-1);
  return (filesys_create(file, initial_size));
}

/* Remove the file which has the name "file." Returns true if it
is succeeded or false if it is not succeeded. */
bool remove(const char* file) {
  if(file==NULL) exit(-1);
  return (filesys_remove(file));
}

/* This function opens the file which is in the path of "file." This
returns fd of the file. */
int open(const char *file){
  return process_add_file(filesys_open(file));
}

/* This returns the size of the file of fd in bytes. */
int filesize(int fd){
  struct file *f= process_get_file(fd);
  if(f==NULL){
    return -1;
  }
  return (int)file_length(f);

}

/* This reads the data of size bytes from the file of fd into the buffer
Returns the actual amount of bytes that this function read. Returns -1 if
it failed to read. If fd is 0, it is the case of stdin */
int read(int fd, void *buffer, unsigned size){
  lock_acquire(&filesys_lock);
  if(fd==0){
    unsigned i=0;
    while(i<size){
      *(char *)(buffer + i) = input_getc();
      i++;
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

/* This function writes size bytes from the buffer to the file of fd
This returns the actual number of bytes that this wrote. If fd is 1,
it is the case of stdout. */
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
    int size1 = file_write(f, buffer, size);
    return size1;
  }
}
/* This find the position and change the next byte to read or write to
position in the file of fd*/
void seek(int fd, unsigned position){
  struct file * f = process_get_file(fd);
  if(f==NULL){
    return;
  }
  file_seek(f,position);
}

/* This function returns the position of next byte which is to be written
or read in the file of fd */
int tell(int fd){
  struct file * f = process_get_file(fd);
  if(f==NULL){
    return -1;
  }
  return file_tell(f);
}

/* This closes the fild of fd */
void close(int fd){
  struct file * f = process_get_file(fd);
  if(f==NULL){
    return;
  }
  process_close_file(fd);
}
/* This runs program which execute "file_name". This passes the arguments
to program which has to be executed this returns the pid of the new child
process. If it failed to create a process or load the program, return -1.
Parent process waits until the child process completes to be created and load
the execution*/
tid_t exec(const *file_name) {
  int child_pid;
  child_pid = process_execute(file_name);
  struct thread* child = get_child_process(child_pid);
  sema_down(&child->load_sema);
  if (child->is_loaded == -1) return -1;
  return child_pid;
}
/* This function waits the process of tid */
unsigned wait(tid_t tid) {
  return (process_wait(tid));
}
