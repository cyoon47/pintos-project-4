#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#include "devices/input.h"
#include "vm/page.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "filesys/inode.h"

#define READDIR_MAX_LEN 14

static void syscall_handler (struct intr_frame *);
bool check_pointer(void *ptr);
bool check_pointer_write(void *ptr);
bool check_args(void *ptr, int args);
bool check_string(char *ptr);

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
	if(!is_user_vaddr(udst))
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

bool check_pointer_write(void *ptr) 
{
  int read_byte = get_user(ptr);
  if(read_byte == -1)
    return false;
  return put_user(ptr, read_byte);
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
  thread_current()->esp = esp;  // save esp

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

        bool created = filesys_create(file_create, initial_size, false);

        f->eax = created;

        break;

      case SYS_REMOVE:
        if(!check_args(esp + 4, 1) || !check_string( *(char **)(esp + 4)))
        {
          thread_exit(-1);
          return;
        }
        char *file_remove = *(char **) (esp + 4);

        bool removed = filesys_remove(file_remove);

        f->eax = removed;

        break;

      case SYS_OPEN:
        if(!check_args(esp + 4, 1) || !check_string( *(char **)(esp + 4)))
        {
          thread_exit(-1);
          return;
        }
        char *file_name = *(char **) (esp + 4);
        struct file *file_ptr = filesys_open(file_name);

        if(file_ptr == NULL)
          f->eax = -1;
        else
        {
          if(inode_isdir(file_get_inode(file_ptr)))
          {
            struct file_map *fmap = malloc(sizeof(struct file_map));
            fmap->fd = thread_current()->next_fd++;
            fmap->dir = (struct dir *) file_ptr;
            fmap->isdir = true;
            list_push_back(&thread_current()->file_list, &fmap->elem);
            f->eax = fmap->fd;
          }
          else
          {
            struct file_map *fmap = malloc(sizeof(struct file_map));
            fmap->fd = thread_current()->next_fd++;
            fmap->file = file_ptr;
            fmap->isdir = false;
            list_push_back(&thread_current()->file_list, &fmap->elem);
            f->eax = fmap->fd;
          }
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
        f->eax = file_length(fs_file);

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

        if(!check_pointer_write(read_buffer) || !check_pointer_write(read_buffer + read_size)) //check buffer
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
            f->eax = file_read(read_file, read_buffer, read_size);
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
            f->eax = file_write(write_file, write_buffer, write_size);
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
          file_seek(seek_file, pos);
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
          f->eax = file_tell(tell_file);
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
          if(close_file_map->isdir)
          {
            dir_close(close_file_map->dir);
          }
          else
          {
            file_close(close_file_map->file);
          }
          list_remove(&close_file_map->elem);
          free(close_file_map);
        }
        break;

      case SYS_MMAP:
        if(!check_args(esp + 4, 2))
        {
          thread_exit(-1);
          return;
        }
        int mmap_fd = *(int *)(esp + 4);
        void *addr = *(void **)(esp + 8);
        if(!get_file(&thread_current()->file_list, mmap_fd))
        {
          f->eax = -1;
          return;
        }
        struct file *file = file_reopen(get_file(&thread_current()->file_list, mmap_fd));
        if(file == NULL || file_length(file) == 0 || addr == 0 || !is_user_vaddr(addr) || pg_ofs(addr) != 0)
        {
          f->eax = -1;
          return;
        }

        uint32_t read_bytes = file_length(file);

        off_t ofs = 0;
        while(read_bytes > 0)
        {
          size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
          size_t page_zero_bytes = PGSIZE - page_read_bytes;

          if (page_lookup(addr) || !add_page(file, ofs, addr, page_read_bytes, page_zero_bytes, true, TYPE_MMAP))
          {
            struct thread *t = thread_current();
            struct list_elem *e;

            for(e = list_begin(&t->mmap_list); e != list_end(&t->mmap_list); e = list_next(e))
            {
              struct mmap_page *mp = list_entry(e, struct mmap_page, elem);
              if(mp->mapid == t->next_mapid)
              {
                hash_delete(&t->s_page_table, &mp->p_entry->elem);
                list_remove(&mp->elem);
                free(mp->p_entry);
                free(mp);
              }
            }

            file_close(file);
            f->eax = -1;
            return;
          }

          read_bytes -= page_read_bytes;
          addr += PGSIZE;
          ofs += PGSIZE;
        }
        f->eax = thread_current()->next_mapid++;
        break;

      case SYS_MUNMAP:
        if(!check_args(esp + 4, 1))
        {
          thread_exit(-1);
          return;
        }
        int mapping = *(int *) (esp + 4);

        thread_munmap(mapping);

        break;
      case SYS_CHDIR:
        if(!check_args(esp + 4, 1) || !check_string( *(char **)(esp + 4)))
        {
          thread_exit(-1);
          return;
        }
        char *chdir_name = *(char **) (esp + 4);
        struct dir *dir = extract_parent_dir(chdir_name);
        char * chdir_file_name = get_name(chdir_name);
        struct inode *inode = NULL;

        if(dir != NULL)
        {
          if(strcmp(chdir_file_name, ".") == 0 || is_root(dir) && strlen(chdir_file_name) == 0)
          {
            free(chdir_file_name);
            thread_current()->curr_dir = dir;
            f->eax = true;
            return;
          }
          else if(strcmp(chdir_file_name, "..") == 0)
          {
            if(!get_parent_dir(dir, &inode))
            {
              free(chdir_file_name);
              f->eax = false;
              return;
            }
          }
          else
          {
            dir_lookup(dir, chdir_file_name, &inode);
          }
        }
        dir_close (dir);
        if(inode == NULL || !inode_isdir(inode))
        {
          free(chdir_file_name);
          f->eax = false;
          return;
        }

        if(dir = dir_open(inode))
        {
          dir_close(thread_current()->curr_dir);
          thread_current()->curr_dir = dir;
          free(chdir_file_name);
          f->eax = true;
          return;
        }
        else
        {
          free(chdir_file_name);
          f->eax = false;
          return;
        }

        break;

      case SYS_MKDIR:
        if(!check_args(esp + 4, 1) || !check_string( *(char **)(esp + 4)))
        {
          thread_exit(-1);
          return;
        }
        char *mkdir_name = *(char **) (esp + 4);
        f->eax = filesys_create(mkdir_name, 0, true);

        break;

      case SYS_READDIR:
        if(!check_args(esp + 4, 2))
        {
          thread_exit(-1);
          return;
        }

        int readdir_fd = *(int *)(esp + 4);
        char *readdir_name = *(char **)(esp + 8);

        if(!check_pointer(readdir_name) || !check_pointer(readdir_name + (READDIR_MAX_LEN) + 1))
        {
          thread_exit(-1);
          return;
        }
        struct file_map *readdir_map = get_file_map(&thread_current()->file_list, readdir_fd);
        if(readdir_map == NULL || !readdir_map->isdir)
        {
          thread_exit(-1);
          return;
        }

        f->eax = dir_readdir(readdir_map->dir, readdir_name);

        break;

      case SYS_ISDIR:
        if(!check_args(esp + 4, 1))
        {
          thread_exit(-1);
          return;
        }
        int isdir_fd = *(int *)(esp + 4);
        struct file_map *isdir_map = get_file_map(&thread_current()->file_list, isdir_fd);
        if(isdir_map == NULL)
        {
          thread_exit(-1);
          return;
        }
        f->eax = isdir_map->isdir;
        break;

      case SYS_INUMBER:
        if(!check_args(esp + 4, 1))
        {
          thread_exit(-1);
          return;
        }
        int inum_fd = *(int *)(esp + 4);
        struct file_map *inum_map = get_file_map(&thread_current()->file_list, inum_fd);
        if(inum_map == NULL)
        {
          thread_exit(-1);
        }
        if(inum_map->isdir)
        {
          f->eax = inode_get_inumber(dir_get_inode(inum_map->dir));
        }
        else
        {
          f->eax = inode_get_inumber(file_get_inode(inum_map->file));
        }

        break;

    }
}
