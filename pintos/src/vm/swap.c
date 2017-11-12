#include "vm/swap.h"
#include "lib/kernel/bitmap.h"
#include "devices/disk.h"
#include "threads/vaddr.h"

struct bitmap *swap_table = NULL;
struct lock swap_lock;

void
swap_init(void)
{
  struct disk *swap_disk = disk_get(1, 1);
  swap_table = bitmap_create(disk_size(swap_disk) * DISK_SECTOR_SIZE / PGSIZE);
  if(swap_table == NULL)
  {
    PANIC("swap_init() : Failed to asssign swap table");
  }
  lock_init(&swap_lock);
}
/* Swap out the frame */
void
swap_out(void *frame, void *vaddr)
{
  if(swap_table == NULL)
  {
    swap_init();
  }
  void *kvpage = pg_round_down(frame);
  struct disk *swap_disk = disk_get(1, 1);
  lock_acquire(&swap_lock);

  disk_sector_t sec_no = swap_empty_slot();
  if(sec_no == 1<<31) //If there is no empty swap slot
  {
    PANIC("swap_out() : Swap-out occurred, but swap space is full.");
  }
  else
  {
    disk_sector_t iter_sec_no;
    for(iter_sec_no = sec_no ; iter_sec_no < sec_no + PGSIZE / DISK_SECTOR_SIZE; iter_sec_no++)
    {
      disk_write(swap_disk, iter_sec_no, kvpage + (iter_sec_no - sec_no) * DISK_SECTOR_SIZE);
    }
    struct s_page_entry *spe = page_lookup(vaddr);
    spe->swap_sec_no = sec_no;
    if(spe->type == TYPE_STACK)
      printf("STACK SWPPAED OUT!!!!!\n");
    spe->type = TYPE_SWAP;
  }
  lock_release(&swap_lock);
  return;
}

/* Swap in the frame to the given page */
void
swap_in(void *vaddr, void *frame)
{
  void *vpage = pg_round_down(vaddr);
  struct s_page_entry *spe = page_lookup(vpage);
  struct disk *swap_disk = disk_get(1, 1);
  lock_acquire(&swap_lock);
  if(spe == NULL || !bitmap_test(swap_table, spe->swap_sec_no * DISK_SECTOR_SIZE / PGSIZE)) //If there is no such slot
  {
    PANIC("swap_in() : Swap in has occurred with wrong address.");
  }
  else
  {
    bitmap_flip(swap_table, spe->swap_sec_no * DISK_SECTOR_SIZE / PGSIZE);
    disk_sector_t iter_sec_no;
    for(iter_sec_no = spe->swap_sec_no; iter_sec_no < spe->swap_sec_no + PGSIZE / DISK_SECTOR_SIZE; iter_sec_no++)
    {
      disk_read(swap_disk, iter_sec_no, frame + (iter_sec_no - spe->swap_sec_no) * DISK_SECTOR_SIZE);
    }
  }
  lock_release(&swap_lock);
  return;
}

/* Find the start sec_no of 4 consecutive empty slot. Return DISK_SECTOR_SIZE when fails. */
disk_sector_t
swap_empty_slot(void)
{
  size_t empty = bitmap_scan_and_flip(swap_table, 0, 1, false);

  if(empty != BITMAP_ERROR)
  {
    return empty * PGSIZE / DISK_SECTOR_SIZE;
  }
  else
  {
    return 1<<31;
  }
}

