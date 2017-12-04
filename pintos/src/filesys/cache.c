#include "filesys/cache.h"
#include "lib/string.h"
#include "lib/debug.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"

void
cache_init(void)
{
	list_init(&cache_list);
	lock_init(&cache_lock);
	cache_cnt = 0;
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
	lock_release(&cache_lock);

	if(type == FILE_READ)
	{
		memcpy(mem_loc, (uint8_t *)&cb->block+ofs, size);
		cb->accessed = true;
		cb->dirty = false;
		cb->num_access--;
	}
	else if(type == FILE_WRITE)
	{
		memcpy((uint8_t *)&cb->block+ofs, mem_loc, size);
		cb->accessed = true;
		cb->dirty = true;
		cb->num_access--;
	}
}

/* evict and load a new disk_sector to cache_block */
struct cache_block *
evict_cache_block(disk_sector_t disk_sector)
{
	/*
	TODO: Implement eviction of cache block 
	*/

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

	return cb;
}