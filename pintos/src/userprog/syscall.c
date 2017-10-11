#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user (const uint8_t *uaddr)
{
	if(!is_user_vaddr(uaddr))
		return -1;
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:"
		: "=&a" (result) : "m" (*uaddr));
	return result;
}

/* 	Writes BYTE to user address UDST.
	UDST must be below PHYS_BASE.
	Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
	if(!is_iser_vaddr(udst))
		return false;
	int error_code;
	asm ("movl $1f, %0; movb %b2, %1; 1:"
		: "=&a" (error_code), "=m" (*udst) : "r" (byte));
	return error_code != -1;
}

/* checks whether the given pointer is valid */
bool check_pointer(void *ptr) 
{
	if(get_user(ptr) == -1)
		return false;

	return true;
}

/* checks args number of arguments for the given pointer */
bool check_args(void *ptr, int args)
{
  int i;
  for(i = 0; i < 4*args; i++)
  {
    if(!check_pointer(ptr+i))
      return false;
  }
  return true;
}

/* checks if the string is within valid pointer range */
bool check_string(char *ptr)
{
  int c = get_user(ptr);
  while(c != -1)
  {
    if(c == '\0')
      return true;
    ptr++;
    c = get_user(ptr);
  }
  return false;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  void *esp = f->esp;
	if(!check_args(esp, 1)) // check given pointer
	{
		thread_exit(-1);
		return;
	}

  	int syscall_no = *(int *)esp;
  	
    switch(syscall_no)
    {
      case SYS_HALT:
        power_off();
        break;
      
      case SYS_EXIT:
        if(!check_args(esp + 4, 1))
        {
          thread_exit(-1);
          return;
        }
        int status;
        status = *(int *) (esp + 4);
        thread_exit(status);
        break;

      case SYS_EXEC:
        if(!check_args(esp + 4, 1) || !check_string( *(char **)(esp + 4) ))
        {
          thread_exit(-1);
          return;
        }
        char *cmd_line = *(char **)(esp + 4);
        f->eax = process_execute(cmd_line);

        break;

      case SYS_WAIT:
        if(!check_args(esp + 4, 1))
        {
          thread_exit(-1);
          return;
        }
        int pid = *(int *) (esp + 4);
        f->eax = process_wait(pid);
        break;

      case SYS_CREATE:

        break;

      case SYS_REMOVE:

        break;

      case SYS_OPEN:

        break;

      case SYS_FILESIZE:

        break;

      case SYS_READ:

        break;

      case SYS_WRITE:
        if(!check_args(esp + 4, 3))
        {
          thread_exit(-1);
          return;
        }

        int fd = *(int *)(esp + 4);
        char *buffer = *(char **)(esp + 8);
        unsigned size = *(unsigned *) (esp + 12);

        if(!check_pointer(buffer) || !check_pointer(buffer + size)) //check buffer
        {
          thread_exit(-1);
          return;
        }

        if(fd == 1) // writing to stdout
        {
          putbuf(buffer, size);
          f->eax = size;
        }
        break;

      case SYS_SEEK:

        break;

      case SYS_TELL:

        break;

      case SYS_CLOSE:

        break;
      }
    }