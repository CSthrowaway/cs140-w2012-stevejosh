#include <string.h>
#include <random.h>
#include "filesys/filesys.h"
#include "filesys/cache.h"
#include "threads/synch.h"

#define CACHE_DIRTY     0x1
#define CACHE_ACCESSED  0x2
#define CACHE_PINNED    0x4
#define CACHE_FREE      0x8
#define CACHE_LOCKED    0x10

struct cache_data
  {
    block_sector_t sector;
    uint32_t status;
    uint32_t in_use;
    struct condition in_use_changed;
  };

struct cache_block
  {
    char data[BLOCK_SECTOR_SIZE];
  };

static struct lock cache_lock;
static struct lock io_lock;
static struct cache_data cache_slot[CACHE_SIZE];
static struct cache_block cache_block[CACHE_SIZE];

void
cache_init (void)
{
  lock_init (&cache_lock);
  lock_init (&io_lock);
  
  int i;
  for (i = 0; i < CACHE_SIZE; ++i)
    {
      cache_slot[i].status = CACHE_FREE;
      cache_slot[i].in_use = 0;
      cond_init (&cache_slot[i].in_use_changed);
    }
}

static void
cache_slot_flush (int slot)
{
  lock_acquire (&io_lock);
  block_write (fs_device, cache_slot[slot].sector, cache_block[slot].data);
  cache_slot[slot].status = 0;
  lock_release (&io_lock);
}

static void
cache_slot_load (int slot)
{
  lock_acquire (&io_lock);
  block_read (fs_device, cache_slot[slot].sector, cache_block[slot].data);
  lock_release (&io_lock);
}

static int
cache_alloc (void)
{
  int slot_to_evict = random_ulong() % CACHE_SIZE;
  while (cache_slot[slot_to_evict].in_use > 0)
    cond_wait (&cache_slot[slot_to_evict].in_use_changed, &cache_lock);

  if (cache_slot[slot_to_evict].status & CACHE_DIRTY)
    cache_slot_flush (slot_to_evict);
  cache_slot[slot_to_evict].status = 0;
  return -1;
}

static int
cache_get (block_sector_t sector)
{
  int i;
  for (i = 0; i < CACHE_SIZE; ++i)
    {
      if (!(cache_slot[i].status & CACHE_FREE) &&
          !(cache_slot[i].status & CACHE_LOCKED) &&
          cache_slot[i].sector == sector)
        return i;
    }
  return -1;
}

static int
cache_begin_operation (block_sector_t sector, bool read_old)
{
  lock_acquire (&cache_lock);
  int slot = cache_get (sector);
  if (slot < 0)
    {
      slot = cache_alloc ();
      cache_slot[slot].sector = sector;
      if (read_old)
        cache_slot_load (slot);
    }
  cache_slot[slot].in_use++;
  cache_slot[slot].status |= CACHE_ACCESSED;
  lock_release (&cache_lock);
  
  return slot;
}

static void
cache_end_operation (int slot, bool written)
{
  lock_acquire (&cache_lock);
  cache_slot[slot].in_use--;
  if (written)
    cache_slot[slot].status |= CACHE_DIRTY;
  cond_broadcast (&cache_slot[slot].in_use_changed, &cache_lock);
  lock_release (&cache_lock);
}

void
cache_read (block_sector_t sector, void *buffer)
{
  int slot = cache_begin_operation (sector, true);
  memcpy (buffer, cache_block[slot].data, BLOCK_SECTOR_SIZE);
  cache_end_operation (slot, false);
}

void
cache_write (block_sector_t sector, const void *data)
{
  int slot = cache_begin_operation (sector, false);  
  memcpy (cache_block[slot].data, data, BLOCK_SECTOR_SIZE);  
  cache_end_operation (slot, true);
}
