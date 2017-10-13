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
        if(!check_args(esp + 4, 2) || !check_string( *(char **)(esp + 4)))
        {
          thread_exit(-1);
          return;
        }
        char *file_create = *(char **) (esp + 4);
        unsigned initial_size = *(unsigned *) (esp + 8);

        acquire_file_lock();
        bool created = filesys_create(file_create, initial_size);
        release_file_lock();

        f->eax = created;

        break;

      case SYS_REMOVE:
        if(!check_args(esp + 4, 1) || !check_string( *(char **)(esp + 4)))
        {
          thread_exit(-1);
          return;
        }
        char *file_remove = *(char **) (esp + 4);

        acquire_file_lock();
        bool removed = filesys_remove(file_remove);
        release_file_lock();

        f->eax = removed;

        break;

      case SYS_OPEN:
        if(!check_args(esp + 4, 1) || !check_string( *(char **)(esp + 4)))
        {
          thread_exit(-1);
          return;
        }
        char *file_name = *(char **) (esp + 4);
        acquire_file_lock();
        struct file *file_ptr = filesys_open(file_name);
        release_file_lock();

        if(file_ptr == NULL)
          f->eax = -1;
        else
        {
          struct file_map *fmap = malloc(sizeof(struct file_map));
          fmap->fd = thread_current()->next_fd++;
          fmap->file = file_ptr;
          list_push_back(&thread_current()->file_list, &fmap->elem);
          f->eax = fmap->fd;
        }

        break;

      case SYS_FILESIZE:
        if(!check_args(esp + 4, 1))
        {
          thread_exit(-1);
          return;
        }
        int fs_fd = *(int *)(esp + 4);
        struct file *fs_file = get_file(&thread_current()->file_list, fs_fd);
        if(fs_file == NULL)
        {
          f->eax = -1;
          return;
        }
        acquire_file_lock();
        f->eax = file_length(fs_file);
        release_file_lock();

        break;

      case SYS_READ:
        if(!check_args(esp + 4, 3))
        {
          thread_exit(-1);
          return;
        }
        int read_fd = *(int *)(esp + 4);
        char *read_buffer = *(char **)(esp + 8);
        unsigned read_size = *(unsigned *) (esp + 12);

        if(!check_pointer(read_buffer) || !check_pointer(read_buffer + read_size)) //check buffer
        {
          thread_exit(-1);
          return;
        }

        if(read_fd == 0) // read from keyboard
        {
          int i;
          for(i = 0; i < read_size; i++)
          {
            read_buffer[i] = input_getc();
          }
          f->eax = read_size;
        }
        else
        {
          struct file *read_file = get_file(&thread_current()->file_list, read_fd);
          if(read_file == NULL)
          {
            f->eax = -1; 
            return;
          }
          else
          {
            acquire_file_lock();
            f->eax = file_read(read_file, read_buffer, read_size);
            release_file_lock();
          } 
        }

        break;

      case SYS_WRITE:
        if(!check_args(esp + 4, 3))
        {
          thread_exit(-1);
          return;
        }

        int write_fd = *(int *)(esp + 4);
        char *write_buffer = *(char **)(esp + 8);
        unsigned write_size = *(unsigned *) (esp + 12);

        if(!check_pointer(write_buffer) || !check_pointer(write_buffer + write_size)) //check buffer
        {
          thread_exit(-1);
          return;
        }

        if(write_fd == 1) // writing to stdout
        {
          putbuf(write_buffer, write_size);
          f->eax = write_size;
        }
        else
        {
          struct file *write_file = get_file(&thread_current()->file_list, write_fd);
          if(write_file == NULL)
          {
            f->eax = -1; 
            return;
          }
          else
          {
            acquire_file_lock();
            f->eax = file_write(write_file, write_buffer, write_size);
            release_file_lock();
          } 
        }
        break;

      case SYS_SEEK:
        if(!check_args(esp + 4, 2))
        {
          thread_exit(-1);
          return;
        }
        int seek_fd = *(int *)(esp + 4);
        unsigned pos = *(unsigned *)(esp + 8);

        struct file *seek_file = get_file(&thread_current()->file_list, seek_fd);
        if(seek_file == NULL)
        {
          return;
        }
        else
        {
          acquire_file_lock();
          file_seek(seek_file, pos);
          release_file_lock();
        }

        break;

      case SYS_TELL:
        if(!check_args(esp + 4, 1))
        {
          thread_exit(-1);
          return;
        }
        int tell_fd = *(int *)(esp + 4);

        struct file *tell_file = get_file(&thread_current()->file_list, tell_fd);
        if(tell_file == NULL)
        {
          f->eax = -1;
          return;
        }
        else
        {
          acquire_file_lock();
          f->eax = file_tell(tell_file);
          release_file_lock();
        }
        break;

      case SYS_CLOSE:
        if(!check_args(esp + 4, 1))
        {
          thread_exit(-1);
          return;
        }
        int close_fd = *(int *)(esp + 4);

        struct file_map *close_file_map = get_file_map(&thread_current()->file_list, close_fd);
        if(close_file_map == NULL)
        {
          return;
        }
        else
        {
          acquire_file_lock();
          file_close(close_file_map->file, pos);
          release_file_lock();
          list_remove(&close_file_map->elem);
          free(close_file_map);
        }

        break;
    }
}
