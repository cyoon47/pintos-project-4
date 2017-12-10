#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hash.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  char *save_ptr;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  
  char *f_name = malloc(strlen(fn_copy) + 1);
  strlcpy(f_name, fn_copy, strlen(fn_copy)+1); // copy file_name to f_name
  f_name = strtok_r(f_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (f_name, PRI_DEFAULT, start_process, fn_copy);

  free(f_name); // free no longer required f_name

  if (tid == TID_ERROR)
  {
    palloc_free_page (fn_copy);
    return -1;
  }

  struct child *ch = NULL;
  struct thread *curr = thread_current();
  struct list_elem *e;
  for(e = list_begin(&curr->child_list); e != list_end(&curr->child_list); e = list_next(e))
  {
    struct child *temp_ch = list_entry(e, struct child, elem);
    if(temp_ch->tid == tid)
    {
      ch = temp_ch;
      break;
    }
  }
  sema_down(&ch->wait_sema); // wait for child to finish loading
  
  if(!ch->load_success)
  {
    return -1;
  }
  
  return tid;
}

/* A thread function that loads a user process and makes it start
   running. */
static void
start_process (void *f_name)
{
  char *file_name = f_name;
  struct intr_frame if_;
  bool success;

  /* Initialize supplemental page table */
  hash_init(&thread_current()->s_page_table, page_hash, page_less, NULL);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);

  struct thread *parent = thread_current()->parent;
  tid_t tid = thread_current()->tid;
  struct child *ch = NULL;
  struct list_elem *e;

  for(e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e))
  {
    struct child *temp_ch = list_entry(e, struct child, elem);
    if(temp_ch->tid == tid)
    {
      ch = temp_ch;
      break;
    }
  }

  if(thread_current()->curr_dir == NULL)
    thread_current()->curr_dir = dir_open_root();

  if (!success) 
  {
    ch->load_success = false;
    sema_up(&ch->wait_sema);
    thread_exit (-1);
  }
  else
  {
    ch->load_success = true;
    sema_up(&ch->wait_sema);
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct list_elem *e;
  struct child *ch = NULL;
  struct thread *curr = thread_current();

  /* search for child with child_tid */
  for(e = list_begin(&curr->child_list); e != list_end(&curr->child_list); e = list_next(e))
    {
      struct child *temp_ch = list_entry(e, struct child, elem);
      if(temp_ch->tid == child_tid)
      {
        ch = temp_ch;
        break;
      }
    }

  if(ch == NULL) // return -1 if no such child was found
    return -1;

  if(!ch->exit)                 // if the child has not exited yet
    sema_down(&ch->wait_sema);  // wait for the child to exit and call sema_up at exit
  
  int exit_status = ch->exit_status;
  list_remove(e);

  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (int status)
{
  struct thread *curr = thread_current ();
  uint32_t *pd;

  printf("%s: exit(%d)\n", curr->name, status); // process exit message

  struct list_elem *e;
  struct child *ch = NULL;

  for(e = list_begin(&curr->parent->child_list); e != list_end (&curr->parent->child_list); e = list_next(e))
  {
    struct child *temp_ch = list_entry(e, struct child, elem);
    if(temp_ch->tid == curr->tid)
    {
      ch = temp_ch;
      break;
    }
  }
  
  ch->exit_status = status;
  ch->exit = true;
  acquire_file_lock();
  file_close(curr->own_file); // close its file to allow write
  close_files(&curr->file_list);
  release_file_lock();

  if(thread_current()->curr_dir != NULL)
    dir_close(thread_current()->curr_dir);
  
  sema_up(&ch->wait_sema); // wake up parent if waiting

  int i;
  for(i = 0; i < curr->next_mapid; i++)
  {
    thread_munmap(i);
  }

  // destroy supplementary page table
  hash_destroy(&thread_current()->s_page_table, destroy_action_func);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = curr->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      curr->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, int argc, char **argv);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* process file_name into arguments */
  char *save_ptr;
  int argc = 0;
  char *argv[128]; // arbitrary limit on the number of arguments
  char *arg;

  char *f_copy = malloc(strlen(file_name) + 1);
  strlcpy(f_copy, file_name, strlen(file_name) + 1);

  for(arg = strtok_r(f_copy, " ", &save_ptr); arg != NULL; arg = strtok_r(NULL, " ", &save_ptr))
  {
    
    argv[argc] = arg;
    argc++;
  }

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;

  process_activate ();

  // acquire access to filesys
  acquire_file_lock();

  /* Open executable file. */
  file = filesys_open (argv[0]);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", argv[0]);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", argv[0]);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, argc, argv))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  thread_current()->own_file = file;
  file_deny_write(file);

 done:
  /* We arrive here whether the load is successful or not. */
  free(f_copy);

  if(!success)
    file_close (file);
  
  release_file_lock();
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Do calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Add a page to supplementary page table */
      if (!add_page(file, ofs, upage, page_read_bytes, page_zero_bytes, writable, TYPE_FILE))
      {
        return false;
      }
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, int argc, char **argv) 
{
  uint8_t *kpage;
  bool success = false;

  /* Set up supplementary page table entry for stack*/
  struct s_page_entry *p_entry = malloc(sizeof(struct s_page_entry));
  if(!p_entry)
    return false;

  p_entry->type = TYPE_STACK;
  p_entry->loaded = false;
  p_entry->upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
  p_entry->writable = true;
  p_entry->allow_swap = false;

  kpage = insert_frame (PAL_USER | PAL_ZERO, p_entry);
  p_entry->loaded = true;

  if(hash_insert(&thread_current()->s_page_table, &p_entry->elem) != NULL)
    return false;

  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
      {
        *esp = PHYS_BASE;

        int i;
        char *arg_ptr[argc]; // array of pointers to arguments in stack

        // push arguments into stack
        for(i = argc-1; i >= 0; i--)
        {
          *esp = (char*) *esp - (strlen(argv[i]) + 1); 
          arg_ptr[i] = (char *) *esp; 
          memcpy(*esp, argv[i], strlen(argv[i]) + 1);
        }

        // round esp to multiple of 4
        while((int) *esp % 4 != 0) 
        {
          *esp = (char *) *esp - sizeof(char);
          char buf = 0;
          memcpy(*esp, &buf, sizeof(char));
        }

        // place null pointer sentinel
        *esp = (char *) *esp - sizeof(char *);
        char *sentinel = 0;
        memcpy(*esp, &sentinel, sizeof(char *));

        // push address of arguments into stack
        for(i = argc - 1; i >= 0; i--)
        {
          *esp = (char *) *esp - sizeof(char *);
          memcpy(*esp, &arg_ptr[i], sizeof(char *));
        }

        // push address to argv
        char **argv_ptr = *esp;
        *esp = (char *) *esp - sizeof(char **);
        memcpy(*esp, &argv_ptr, sizeof(char **));

        // push argc
        *esp = (char *) *esp - sizeof(int);
        memcpy(*esp, &argc, sizeof(int));

        // push fake return address
        void *ret = 0;
        *esp = (char *) *esp - sizeof(void *);
        memcpy(*esp, &ret, sizeof(void *));

      }
      else
      {
        free(p_entry);
        free_frame (kpage);
      }
    }

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
