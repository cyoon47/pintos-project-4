#include "vm/page.h"
#include "devices/disk.h"
#include "lib/kernel/list.h"

void swap_init(void);
void swap_out(void *, void *);
void swap_in(void *, void *);
disk_sector_t swap_empty_slot(void);
