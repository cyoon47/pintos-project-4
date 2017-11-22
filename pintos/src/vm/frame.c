#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "vm/frame.h"
#include "lib/debug.h"
#include "vm/swap.c"
#include "userprog/pagedir.h"

/* initialize frame table */
void init_frame_table(void)
{
	list_init(&frame_table);
	lock_init(&frame_lock);
}

/* get a free frame*/
void * insert_frame(enum palloc_flags flags, struct s_page_entry *p_entry)
{
	ASSERT((flags & PAL_USER));		// make sure to get from user pool

	void *frame = palloc_get_page(flags);
	while(frame == NULL)
	{
    	frame = evict_frame(flags);
    	lock_release(&frame_lock);
    }
	if(frame == NULL)
  		PANIC("evict failed");

  	add_frame(frame, p_entry);
	return frame;
}

/* free the allocated frame */
void free_frame(void *frame)
{
	struct list_elem *e;
	lock_acquire(&frame_lock);

	for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
	{
		struct frame_entry *fe = list_entry(e, struct frame_entry, elem);

		if(fe->frame == frame){
			list_remove(e);
			free(fe);
			palloc_free_page(frame);
			break;
		}
	}

	lock_release(&frame_lock);
}

/* add frame to frame table */
void add_frame(void *frame, struct s_page_entry *p_entry)
{
	struct frame_entry *fe = malloc(sizeof(struct frame_entry));
	fe->frame = frame;
	fe->owner_thread = thread_current();
	p_entry->allow_swap = false;
	fe->loaded_page = p_entry;

	lock_acquire(&frame_lock);
	list_push_back(&frame_table, &fe->elem);
	lock_release(&frame_lock);
}

/* evict frame from frame table */
void * evict_frame(enum palloc_flags flags)
{
  struct list_elem *e;

  lock_acquire(&frame_lock);
  e = list_begin(&frame_table);

  while(true)
  {
    struct frame_entry *fe = list_entry(e, struct frame_entry, elem);
    if(fe->loaded_page->allow_swap)
    {
    	struct thread *t = fe->owner_thread;
    	if(pagedir_is_accessed(t->pagedir, fe->loaded_page->upage))
	      pagedir_set_accessed(t->pagedir, fe->loaded_page->upage, false);
	    else
	    {
	      fe->loaded_page->type = TYPE_SWAP;
	      fe->loaded_page->swap_sec_no = swap_out(fe->frame);
	      
	      fe->loaded_page->loaded = false;
	      list_remove(&fe->elem);
	      pagedir_clear_page(t->pagedir, fe->loaded_page->upage);
	      palloc_free_page(fe->frame);
	      free(fe);
	      return palloc_get_page(flags);
	    }  
    }
    e = list_next(e);
    if(e == list_end(&frame_table))
      e = list_begin(&frame_table);
  }
}
