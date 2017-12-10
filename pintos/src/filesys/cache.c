#include "filesys/cache.h"
#include "lib/string.h"
#include "lib/debug.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "devices/timer.h"

#define WRITE_BACK_PERIOD (TIMER_FREQ*3)

thread_func thread_write_back;
thread_func thread_read_ahead;

void
cache_init(void)
{
	list_init(&cache_list);
	lock_init(&cache_lock);
	cache_cnt = 0;
	thread_create("cache_write_back", PRI_MAX, thread_write_back, NULL);
}

/* searches the cache list to see if disk_sector is in cache */
struct cache_block*
cache_lookup(disk_sector_t disk_sector)
{
	struct list_elem *e;
	struct cache_block *cb;
	for(e = list_begin(&cache_list); e != list_end(&cache_list); e = list_next(e))
	{
		cb = list_entry(e, struct cache_block, elem);
		if(cb->disk_sector == disk_sector)
		{
			return cb;
		}
	}
	return NULL;
}

/* read or write to the cache block */
void
access_cache_block(disk_sector_t disk_sector, void *mem_loc, off_t ofs, size_t size, enum access_mode type)
{
	lock_acquire(&cache_lock);
	struct cache_block *cb = cache_lookup(disk_sector);
	
	if(cb == NULL)
	{
		cb = evict_cache_block(disk_sector);
		if(cb == NULL)
		{
			PANIC("Failed to evict a cache block!");
		}
	}
	else
	{
		cb->num_access++;
	}
	
	cb->accessed = true;
	lock_release(&cache_lock);

	if(type == FILE_READ)
	{
		memcpy(mem_loc, (uint8_t *)&cb->block+ofs, size);
		cb->num_access--;
	}
	else if(type == FILE_WRITE)
	{
		memcpy((uint8_t *)&cb->block+ofs, mem_loc, size);
		cb->dirty = true;
		cb->num_access--;
	}
}

/* evict and load a new disk_sector to cache_block */
struct cache_block *
evict_cache_block(disk_sector_t disk_sector)
{
	/* if we can add more cache blocks */
	struct cache_block *cb;
	if(cache_cnt < MAX_CACHE_SIZE)
	{
		cache_cnt++;
		cb = malloc(sizeof(struct cache_block));
		if(cb == NULL)
		{
			return NULL;
		}
		list_push_back(&cache_list, &cb->elem);
	}
	else
	{
		struct list_elem *e = list_begin(&cache_list);
		while(true)
		{
			cb = list_entry(e, struct cache_block, elem);
			if(cb->num_access == 0) // skip caches being accessed
			{
				if(cb->accessed)
				{
					cb->accessed = false;
				}
				else
				{
					if(cb->dirty)
					{
						disk_write(filesys_disk, cb->disk_sector, &cb->block);
					}
					break;
				}
			}
			e = list_next(e);
			if(e == list_end(&cache_list))
				e = list_begin(&cache_list);
		}
	}
	// load new disk_sector to cache
	cb->num_access = 1;
	cb->disk_sector = disk_sector;
	disk_read(filesys_disk, cb->disk_sector, &cb->block);
	cb->dirty = false;
	return cb;
}

void
write_back(void)
{
	struct list_elem *e;
	for(e = list_begin(&cache_list); e != list_end(&cache_list); e = list_next(e))
	{
		struct cache_block *cb = list_entry(e, struct cache_block, elem);
		if(cb->dirty)
		{
			disk_write(filesys_disk, cb->disk_sector, &cb->block);
			cb->dirty = false;
		}
	}
}

void
thread_write_back(void *aux UNUSED)
{
	while(true)
	{
		write_back();
		timer_sleep(WRITE_BACK_PERIOD);
	}
}

// create a read ahead thread to asynchronously load the next sector
void
read_ahead(disk_sector_t disk_sector, int priority)
{
	disk_sector_t *next_sector = malloc(sizeof(disk_sector_t));
	if(next_sector == NULL)
		return;
	*next_sector = disk_sector + 1;
	thread_create("read_ahead", priority, thread_read_ahead, next_sector);
}

void
thread_read_ahead(void *aux)
{
	disk_sector_t disk_sector = * (disk_sector_t *) aux;
	lock_acquire(&cache_lock);
	struct cache_block *cb = cache_lookup(disk_sector);
	if(cb == NULL)
	{
		cb = evict_cache_block(disk_sector);
		cb->accessed = true;
	}
	lock_release(&cache_lock);
	free(aux);
}