#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "vm/frame.h"
#include "lib/debug.h"
#include "vm/swap.c"

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
	if(frame == NULL)
	{
		//PANIC("insert_frame - ran out of frames to allocate");
    frame = evict_frame(flags, p_entry);
	}

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
	fe->loaded_page = p_entry;

	lock_acquire(&frame_lock);
	list_push_back(&frame_table, &fe->elem);
	lock_release(&frame_lock);
}

/* evict frame from frame table */
void * evict_frame(enum palloc_flags flags, struct s_page_entry *p_entry)
{
  /* victim is selected unthoughtfully for now */
  struct list_elem *e;

  lock_acquire(&frame_lock);
  e = list_begin(&frame_table);

  struct frame_entry *fe = list_entry(e, struct frame_entry, elem);

  if(pagedir_is_dirty(fe->owner_thread->pagedir, fe->loaded_page->upage))
  {
    if(fe->loaded_page->type == TYPE_FILE)
    {
      file_write_at(fe->loaded_page->file, fe->frame,
                    fe->loaded_page->read_bytes, fe->loaded_page->ofs);
    }
    else if(fe->loaded_page->type == TYPE_SWAP)
    {
      swap_out(fe->frame, fe->loaded_page->upage);
    }
    else //TYPE_STACK
    {
      swap_out(fe->frame, fe->loaded_page->upage);
    }
  }
  else
  {
  }
  fe->loaded_page->loaded = false;
  list_remove(e);
  lock_release(&frame_lock);

  pagedir_clear_page(fe->owner_thread->pagedir, fe->loaded_page->upage);
  void * temp = fe->frame;
  free_frame(fe->frame);

  return palloc_get_page(flags);
}
