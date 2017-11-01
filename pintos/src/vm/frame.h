#ifndef VM_FRAME_H
#define VM_FRAME_H

struct list frame_table;		// list of frames as frame table
struct lock frame_lock;			// lock to control access to frame table


struct frame_entry{
	void *frame;
	struct list_elem elem;
	struct thread *owner_thread;
};

void init_frame_table(void); 
void * get_frame(enum palloc_flags);
void free_frame(void *);
void add_frame(void *);

#endif