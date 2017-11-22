#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "vm/page.h"

struct list frame_table;		// list of frames as frame table
struct lock frame_lock;			// lock to control access to frame table


struct frame_entry{
	void *frame;
	struct list_elem elem;
	struct thread *owner_thread;
	struct s_page_entry *loaded_page;
};

void init_frame_table(void); 
void * insert_frame(enum palloc_flags, struct s_page_entry *);
void free_frame(void *);
void add_frame(void *, struct s_page_entry *);
void * evict_frame(enum palloc_flags);

#endif
