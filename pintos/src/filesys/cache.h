#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/disk.h"
#include "threads/synch.h"
#include <list.h>
#include "filesys/off_t.h"

#define MAX_CACHE_SIZE 64

struct list cache_list;
struct lock cache_lock;
unsigned cache_cnt;

enum access_mode
{
	FILE_READ,
	FILE_WRITE
};

struct cache_block
{
	uint8_t block[DISK_SECTOR_SIZE];	/* contains the block data */
	disk_sector_t disk_sector;			/* corresponding disk sector */
	bool accessed;						/* accessed bit for eviction */	
	bool dirty;							/* check if block is dirty */
	unsigned num_access;				/* use reverse semaphore-like variable to control eviction */

	struct list_elem elem;				/* insertion into cache_list */
};

void cache_init(void);
struct cache_block* cache_lookup(disk_sector_t);
void access_cache_block(disk_sector_t, void *, off_t, size_t, enum access_mode);
struct cache_block* evict_cache_block(disk_sector_t);

#endif
