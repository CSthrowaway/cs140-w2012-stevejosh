#include <string.h>
#include <random.h>
#include <debug.h>
#include "filesys/filesys.h"
#include "filesys/cache.h"
#include "threads/synch.h"

#define CACHE_DIRTY     0x1
#define CACHE_ACCESSED  0x2
#define CACHE_FREE      0x4
#define CACHE_LOCKED    0x8

/* cache_data contains the metadata for a single cache slot. */
struct cache_data
  {
    int sector;
    uint32_t status;
    uint32_t in_use;
    struct condition cond;
  };

/* cache_block provides a convenient way to declare and access
   BLOCK_SECTOR_SIZE chunks of data. */
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
  
  /* Clear all of the cache metadata. By default, all cache slots will contain
     sector -1 (meaning no sector). */
  int i;
  for (i = 0; i < CACHE_SIZE; ++i)
    {
      cache_slot[i].sector = -1;
      cache_slot[i].status = CACHE_FREE;
      cache_slot[i].in_use = 0;
      cond_init (&cache_slot[i].cond);
    }
}

static void
cache_slot_flush (int slot)
{
  int sector = cache_slot[slot].sector;
  
  /* In order to ensure that someone else doesn't try to use this slot while
     we're writing the data out to disk, we need to both lock the slot AND
     make it look like no sector occupies it. */
  cache_slot[slot].status |= CACHE_LOCKED;
  cache_slot[slot].sector = -1;
  lock_release (&cache_lock);

  lock_acquire (&io_lock);
  block_write (fs_device, sector, cache_block[slot].data);
  cache_slot[slot].status = 0;
  lock_release (&io_lock);

  lock_acquire (&cache_lock);
  cache_slot[slot].status &= ~CACHE_LOCKED;
}

static void
cache_slot_load (int slot, int sector)
{
  cache_slot[slot].status |= CACHE_LOCKED;
  cache_slot[slot].sector = -1;
  lock_release (&cache_lock);

  lock_acquire (&io_lock);
  block_read (fs_device, sector, cache_block[slot].data);
  lock_release (&io_lock);

  lock_acquire (&cache_lock);
  cache_slot[slot].status &= ~CACHE_LOCKED;
  cache_slot[slot].sector = sector;
  cond_broadcast (&cache_slot[slot].cond, &cache_lock);
}

static int
cache_alloc (void)
{
  int slot_to_evict;
  // TODO : Replace with clock algorithn.
  do {
    slot_to_evict = random_ulong() % CACHE_SIZE;
  } while (cache_slot[slot_to_evict].status & CACHE_LOCKED);

  while (cache_slot[slot_to_evict].in_use > 0)
    cond_wait (&cache_slot[slot_to_evict].cond, &cache_lock);

  if (cache_slot[slot_to_evict].status & CACHE_DIRTY)
    cache_slot_flush (slot_to_evict);

  cache_slot[slot_to_evict].status = 0;
  cache_slot[slot_to_evict].sector = -1;
  return -1;
}

/* Search the buffer cache for a slot containing the given sector. Returns -1
   if the given sector is not in the buffer cache.
   NOTE : Assumes that cache_lock has already been acquired. */
static int
cache_get (block_sector_t sector)
{
  int i;
  for (i = 0; i < CACHE_SIZE; ++i)
    {
      if (!(cache_slot[i].status & CACHE_FREE) &&
          cache_slot[i].sector == sector)
        return i;
    }
  return -1;
}

/* Prepares the buffer cache to begin an operation on the given sector. If the
   sector is not already in a slot, evicts another sector and brings the given
   sector into a slot. If read_old is true, then the sector's current memory
   will also be brought into the cache. Returns the cache slot holding the
   given sector (which is guaranteed to be in a slot once this function
   returns to the caller). */
static int
cache_begin_operation (block_sector_t sector)
{
  lock_acquire (&cache_lock);
  int slot;

  while (true)
    {
      slot = cache_get (sector);
      if (slot < 0)
        {
          slot = cache_alloc ();
          cache_slot_load (slot, sector);
        }
      else
        {
          /* It's possible that the slot is currently locked and is being
             brought in from disk. If that's the case, we need to wait until
             it's unlocked. */
          while (cache_slot[slot].status & CACHE_LOCKED)
            cond_wait (&cache_slot[slot].cond, &cache_lock);
          
          /* It's also possible, however unlikely, that someone came in before
             we were able to get the lock and evicted the sector we were
             waiting on. In that case, we have to try, try again. */
          if (cache_slot[slot].sector != sector)
            continue;
        }
      break;
    }

  ASSERT (!(cache_slot[slot].status & CACHE_LOCKED));
  ASSERT (cache_slot[slot].sector == sector);
  
  cache_slot[slot].in_use++;
  cache_slot[slot].status |= CACHE_ACCESSED;
  lock_release (&cache_lock);  
  return slot;
}

/* Notifies the buffer cache that the given slot is no longer being used by
   the caller. Signals anyone who was waiting on this slot. */
static void
cache_end_operation (int slot, bool written)
{
  lock_acquire (&cache_lock);
  cache_slot[slot].in_use--;
  if (written)
    cache_slot[slot].status |= CACHE_DIRTY;
  cond_broadcast (&cache_slot[slot].cond, &cache_lock);
  lock_release (&cache_lock);
}

/* Reads the given sector into the given buffer, leveraging the cache where
   available. If the sector is not already in the cache, it will be brought in
   for future use. */
void
cache_read (block_sector_t sector, void *buffer)
{
  int slot = cache_begin_operation (sector);
  memcpy (buffer, cache_block[slot].data, BLOCK_SECTOR_SIZE);
  cache_end_operation (slot, false);
}

/* Writes the given sector to the buffer cache (and, later, to disk). */
void
cache_write (block_sector_t sector, const void *data)
{
  int slot = cache_begin_operation (sector);  
  memcpy (cache_block[slot].data, data, BLOCK_SECTOR_SIZE);  
  cache_end_operation (slot, true);
}
