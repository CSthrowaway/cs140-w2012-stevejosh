#include "devices/block.h"
#include <stdbool.h>

#define CACHE_SIZE 64

void cache_init (void);
void cache_read (block_sector_t sector, void *buffer, off_t off, unsigned size);
void cache_write (block_sector_t sector, const void *data,
                  off_t off, unsigned size);
void cache_zero (block_sector_t sector);
