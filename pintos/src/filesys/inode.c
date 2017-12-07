#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DISK_NUM_PTR 128
#define INDIRECT_BLOCK_SIZE (DISK_NUM_PTR*DISK_SECTOR_SIZE)
#define MAX_FILE_SIZE 1<<23

/* On-disk inode.
   Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    disk_sector_t start_block;
    unsigned allocated;
    unsigned inner_index;
    unsigned outer_index;
    uint32_t unused[122];               /* Not used. */
  };

struct indirect_block
{
  disk_sector_t disk_ptr[DISK_NUM_PTR];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    disk_sector_t sector;               /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    off_t length;
    disk_sector_t start_block;
    unsigned allocated;
    unsigned inner_index;
    unsigned outer_index;
  };

bool inode_allocate(struct inode_disk *);
void inode_deallocate(struct inode *);
void inode_grow(struct inode *, off_t);

/* Returns the disk sector that contains byte offset POS within
   INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  int index;
  disk_sector_t indirect_block[DISK_NUM_PTR];
  ASSERT (inode != NULL);
  if (pos < inode->length)
  {
    
    disk_read(filesys_disk, inode->start_block, &indirect_block);
    index = pos / (INDIRECT_BLOCK_SIZE);
    disk_read(filesys_disk, indirect_block[index], &indirect_block);
    pos = pos % INDIRECT_BLOCK_SIZE;
    return indirect_block[pos/DISK_SECTOR_SIZE];
  }
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = (length > MAX_FILE_SIZE) ? MAX_FILE_SIZE : length;
      disk_inode->magic = INODE_MAGIC;
      if (inode_allocate(disk_inode))
        {
          disk_write (filesys_disk, sector, disk_inode);
          success = true; 
        } 
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  struct inode_disk data;
  disk_read (filesys_disk, inode->sector, &data);
  inode->length = data.length;
  inode->start_block = data.start_block;
  inode->allocated = data.allocated;
  inode->inner_index = data.inner_index;
  inode->outer_index = data.outer_index;
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          inode_deallocate(inode);
        }
      else
      {
        struct inode_disk *data = malloc(sizeof(struct inode_disk));
        data->length = inode->length;
        data->magic = INODE_MAGIC;
        data->start_block = inode->start_block;
        data->allocated = inode->allocated;
        data->inner_index = inode->inner_index;
        data->outer_index = inode->outer_index;

        disk_write(filesys_disk, inode->sector, data);

        free(data);
      }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  if(offset >= inode_length(inode))
    return bytes_read;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      access_cache_block(sector_idx, buffer+bytes_read, sector_ofs, chunk_size, FILE_READ);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  if(offset + size > inode_length(inode))
  {
    inode_grow(inode, offset + size);
    inode->length = offset + size;

  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      access_cache_block(sector_idx, buffer+bytes_written, sector_ofs, chunk_size, FILE_WRITE);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->length;
}

bool inode_allocate(struct inode_disk *disk_inode)
{
  struct inode *inode = malloc(sizeof(struct inode));
  inode->length = 0;
  inode->allocated = 0;
  inode->inner_index = 0;
  inode->outer_index = 0;
  inode_grow(inode, disk_inode->length);

  memcpy(&disk_inode->start_block, &inode->start_block, sizeof(disk_sector_t));
  memcpy(&disk_inode->allocated, &inode->allocated, sizeof(unsigned));
  memcpy(&disk_inode->inner_index, &inode->inner_index, sizeof(unsigned));
  memcpy(&disk_inode->outer_index, &inode->outer_index, sizeof(unsigned));
  
  free(inode);
  return true;
}

void inode_deallocate(struct inode *inode)
{
  size_t num_sectors = bytes_to_sectors(inode_length(inode));
  struct indirect_block inner_block;
  struct indirect_block outer_block;
  int i, j;
  disk_read(filesys_disk, inode->start_block, &inner_block);

  for(i = 0; i < DISK_NUM_PTR; i++)
  {
    disk_read(filesys_disk, inner_block.disk_ptr[i], &outer_block);
    for(j = 0; j < DISK_NUM_PTR; j++)
    {
      free_map_release(outer_block.disk_ptr[j], 1);
      num_sectors--;
      if(num_sectors == 0)
        break;
    }
    free_map_release(inner_block.disk_ptr[i], 1);
    if(num_sectors == 0)
      break;
  }

  free_map_release(inode->start_block, 1);
}

void inode_grow(struct inode *inode, off_t new_length)
{
  struct indirect_block inner_block;
  struct indirect_block outer_block;
  static char zeros[DISK_SECTOR_SIZE];
  size_t add_sectors = bytes_to_sectors(new_length) - bytes_to_sectors(inode_length(inode));
  if(add_sectors == 0)
    return;

  if(!inode->allocated)
  {
    free_map_allocate(1, &inode->start_block);
    inode->allocated++;
  }
  else
  {
    disk_read(filesys_disk, inode->start_block, &inner_block);
  }

  while(inode->inner_index < DISK_NUM_PTR)
  {
    if(inode->outer_index == 0)
    {
      free_map_allocate(1, &inner_block.disk_ptr[inode->inner_index]);
    }
    else
    {
      disk_read(filesys_disk, inner_block.disk_ptr[inode->inner_index], &outer_block);
    }

    while(inode->outer_index < DISK_NUM_PTR)
    {
      free_map_allocate(1, &outer_block.disk_ptr[inode->outer_index]);
      disk_write(filesys_disk, outer_block.disk_ptr[inode->outer_index], zeros);
      inode->outer_index++;
      add_sectors--;
      if(add_sectors == 0)
        break;
    }

    disk_write(filesys_disk, inner_block.disk_ptr[inode->inner_index], &outer_block);
    if(inode->outer_index == DISK_NUM_PTR)
    {
      inode->outer_index = 0;
      inode->inner_index++;
    }

    if(add_sectors == 0)
      break;
  }
  disk_write(filesys_disk, inode->start_block, &inner_block);
}
