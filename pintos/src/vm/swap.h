#include "vm/page.h"
#include "devices/disk.h"
#include "lib/kernel/list.h"

struct lock swap_lock;
struct disk *swap_disk;
struct bitmap *swap_table;

void swap_init(void);
disk_sector_t swap_out(void *);
void swap_in(disk_sector_t, void *);
disk_sector_t swap_empty_slot(void);
