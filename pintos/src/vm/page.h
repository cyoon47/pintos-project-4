#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "devices/disk.h"

#define STACK_LIMIT  (1 << 23) // 8MB stack size

#define STACK_LIMIT  (1 << 23) // 8MB stack size

enum page_type
{
	TYPE_FILE,
	TYPE_SWAP,
	TYPE_STACK
};

struct s_page_entry{

	enum page_type type; 	// type of page
	bool loaded;			// whether the page is loaded in physical memory
	struct file *file;

	int32_t ofs;
	void *upage;
	uint32_t read_bytes;
	uint32_t zero_bytes;
	bool writable;

  disk_sector_t swap_sec_no;

	struct hash_elem elem;
};
unsigned page_hash (const struct hash_elem *, void *);
bool page_less (const struct hash_elem *, const struct hash_elem *, void *);
void destroy_action_func (struct hash_elem *, void *);
struct s_page_entry * page_lookup (const void *);
bool add_page(struct file *, int32_t, uint8_t *, uint32_t, uint32_t, bool, enum page_type);
bool grow_stack(void *);
bool load_swap (struct s_page_entry *);

#endif
