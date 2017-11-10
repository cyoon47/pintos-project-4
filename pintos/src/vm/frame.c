#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "vm/frame.h"
#include "lib/debug.h"

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
	if(frame)
	{
		add_frame(frame, p_entry);
	}
	else // ran out of frames. panic for now
	{
		PANIC("insert_frame - ran out of frames to allocate");
	}

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
