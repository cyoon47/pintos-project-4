#include "vm/page.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "vm/swap.h"
#include <hash.h>
#include "filesys/file.h"
#include "lib/string.h"

/* Hash function for hash table */
unsigned
page_hash (const struct hash_elem *p, void *aux UNUSED)
{
	const struct s_page_entry *spe = hash_entry(p, struct s_page_entry, elem);
	return hash_bytes(&spe->upage, sizeof spe->upage );
}

/* Comparison function for hash table */
bool
page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
	const struct s_page_entry *spea = hash_entry(a, struct s_page_entry, elem);
	const struct s_page_entry *speb = hash_entry(b, struct s_page_entry, elem);
	return spea->upage < speb-> upage;
}

/* Function to be called when supplementary page table is destroyed */
void destroy_action_func (struct hash_elem *e, void *aux UNUSED)
{
	struct s_page_entry *p_entry = hash_entry(e, struct s_page_entry, elem);

	// if page in frame, free the frame
	if(p_entry->loaded)
	{

		free_frame(pagedir_get_page(thread_current()->pagedir, p_entry->upage));
		pagedir_clear_page(thread_current()->pagedir, p_entry->upage);
	}
	free(p_entry);
}

/* Find entry given user virtual address */
struct s_page_entry *
page_lookup (const void *user_address)
{
	struct s_page_entry spe;
	struct hash_elem *e;

	spe.upage = pg_round_down(user_address);
	e = hash_find(&thread_current()->s_page_table, &spe.elem);
	return e != NULL ? hash_entry (e, struct s_page_entry, elem) : NULL;
}


/* Add a page to the supplementary page table. Returns success */
bool
add_page(struct file *file, int32_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable, enum page_type type)
{
	struct s_page_entry *p_entry = malloc(sizeof(struct s_page_entry));
	if(!p_entry)
		return false;

	p_entry->loaded = false;
	p_entry->file = file;
	p_entry->ofs = ofs;
	p_entry->upage = upage;
	p_entry->read_bytes = read_bytes;
	p_entry->zero_bytes = zero_bytes;
	p_entry->writable = writable;
	p_entry->allow_swap = true;

	// Add a file
	if(type == TYPE_FILE)
	{
		p_entry->type = TYPE_FILE;
	}

	else if(type == TYPE_MMAP)
	{
		p_entry->type = TYPE_MMAP;
		struct mmap_page *mp = malloc(sizeof(struct mmap_page));
		if(!mp)
		{
			free(p_entry);
			return false;
		}
		mp->mapid = thread_current()->next_mapid;
		mp->p_entry = p_entry;
		list_push_back(&thread_current()->mmap_list, &mp->elem);
	}

	if(hash_insert(&thread_current()->s_page_table, &p_entry->elem) != NULL)
		return false;
	return true;
}

/* Grow stack and return success */
bool
grow_stack(void *address)
{
	void *stack_addr = pg_round_down(address);
	if(stack_addr < PHYS_BASE - STACK_LIMIT) // over stack limit
	{
		return false;
	}

	struct s_page_entry *p_entry = malloc(sizeof(struct s_page_entry));
	if(!p_entry)
		return false;

	p_entry->type = TYPE_STACK;
	p_entry->loaded = true;
	p_entry->upage = stack_addr;
	p_entry->writable = true;
	p_entry->allow_swap = false;

	void *frame = insert_frame(PAL_USER, p_entry);
	if(!frame){
		free(p_entry);
		return false;
	}

	bool success = install_page(stack_addr, frame, true);
	if(!success)
	{
		free_frame(frame);
		free(p_entry);
		return false;
	}

	if(hash_insert(&thread_current()->s_page_table, &p_entry->elem) != NULL)
	{
		return false;
	}
	return true;
}

bool load_swap (struct s_page_entry *p_entry)
{
	p_entry->allow_swap = false;
	void *frame = insert_frame(PAL_USER, p_entry);
	if(!frame)
	{
		return false;
	}
	if (!install_page (p_entry->upage, frame, p_entry->writable)) 
    {
      free_frame (frame);
      return false; 
    }
    swap_in(p_entry->swap_sec_no, frame);
    p_entry->loaded = true;
    p_entry->allow_swap = true;
    return true;
}

bool load_file(struct s_page_entry *p_entry)
{
	void *frame;
	p_entry->allow_swap = false;
	if(p_entry->read_bytes == 0)
		frame = insert_frame(PAL_USER | PAL_ZERO, p_entry);
	else
		frame = insert_frame(PAL_USER, p_entry);

	if(frame == NULL)
		return false;

	if(!install_page(p_entry->upage, frame, p_entry->writable))
	{
		free_frame (frame);
		return false;
	}
	
	if(p_entry->read_bytes > 0)
      {
      	file_seek (p_entry->file, p_entry->ofs);
        /* Load this page. */
        if (file_read (p_entry->file, frame, p_entry->read_bytes) != (int) p_entry->read_bytes)
          {
            free_frame (frame);
            return false; 
          }
        memset (frame + p_entry->read_bytes, 0, p_entry->zero_bytes);
      }
	
	p_entry->loaded = true;
	p_entry->allow_swap = true;
	return true;
}








