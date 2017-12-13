#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/disk.h"
#include "filesys/file.h"

struct bitmap;

void inode_init (void);
bool inode_create (disk_sector_t, off_t, bool);
struct inode *inode_open (disk_sector_t);
struct inode *inode_reopen (struct inode *);
disk_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);
bool inode_isdir(struct inode *inode);
disk_sector_t inode_get_parent(struct inode *inode);
void inode_add_dir(disk_sector_t sector, disk_sector_t dir_sector);
int inode_get_open_cnt(struct inode *inode);
void acquire_inode_lock(struct inode *inode);
void release_inode_lock(struct inode *inode);

#endif /* filesys/inode.h */
