#include <string.h>
#include <random.h>
#include <debug.h>
#include "devices/timer.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"
#include "threads/synch.h"
#include "threads/thread.h"

#define MAX_SECTORS     (8 * 1024 * 1024 / BLOCK_SECTOR_SIZE)

/* cache_data contains the metadata for a single cache slot. */
struct cache_data
  {
    bool dirty;
    bool accessed;
    int sector;
    int new_sector;
    struct lock lock;
  };

/* cache_block provides a convenient way to declare and access
   BLOCK_SECTOR_SIZE chunks of data. */
struct cache_block
  {
    char data[BLOCK_SECTOR_SIZE];
  };

static struct lock cache_lock;
static struct lock io_lock;
static struct cache_data slot[CACHE_SIZE];
static struct cache_block block[CACHE_SIZE];

static void
cache_daemon (void *aux UNUSED)
{
  while (true)
    {
      timer_ssleep (30);
      cache_flush ();
    }
}

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
      slot[i].sector = -1;
      slot[i].new_sector = -1;
      slot[i].dirty = false;
      slot[i].accessed = false;
      lock_init (&slot[i].lock);
    }

  thread_create ("cache_daemon", PRI_DEFAULT, cache_daemon, NULL);
}

static void
cache_slot_flush (int slotid, int sector)
{
  ASSERT (slotid >= 0 && slotid < CACHE_SIZE);
  ASSERT (sector >= 0 && sector < MAX_SECTORS);
 
  lock_acquire (&io_lock);
  block_write (fs_device, sector, block[slotid].data);
  lock_release (&io_lock);
  
  slot[slotid].dirty = false;
}

void
cache_flush (void)
{
  int i;
  for (i = 0; i < CACHE_SIZE; ++i)
    {
      lock_acquire (&cache_lock);
      if (slot[i].new_sector < 0 &&
          slot[i].dirty)
        {
          lock_release (&cache_lock);
          lock_acquire (&slot[i].lock);
          cache_slot_flush (i, slot[i].sector);
          lock_release (&slot[i].lock);
        }
      else
        lock_release (&cache_lock);
    }
}

/* Force the given cache slot to load sector data for the given sector from
   disk.
   NOTE : Assumes that cache_lock has already been acquired. */
static void
cache_slot_load (int slotid, int sector)
{
  ASSERT (slotid >= 0 && slotid < CACHE_SIZE);
  ASSERT (sector >= 0 && sector < MAX_SECTORS);
  
  lock_acquire (&io_lock);
  block_read (fs_device, sector, block[slotid].data);
  lock_release (&io_lock);
}

static int
cache_alloc (int new_sector)
{
  int evict;
  // TODO : Clockzy.
  while (true)
    {
      evict = random_ulong() % CACHE_SIZE;
      if (slot[evict].new_sector < 0)
        break;
    }
  
  slot[evict].new_sector = new_sector;
  lock_release (&cache_lock);
  
  lock_acquire (&slot[evict].lock);
  if (slot[evict].dirty)
    cache_slot_flush (evict, slot[evict].sector);
  
  slot[evict].sector = new_sector;
  slot[evict].new_sector = -1;
  slot[evict].accessed = false;
  return evict;
}

static int
cache_get_slot (int sector)
{
  ASSERT (sector >= 0 && sector < MAX_SECTORS);
  while (true)
    {
      lock_acquire (&cache_lock);
      int slotid = -1;
      {
        int i;
        for (i = 0; i < CACHE_SIZE && slotid < 0; ++i)
          if (slot[i].sector == sector ||
              slot[i].new_sector == sector)
            slotid = i;
      }
      
      if (slotid < 0)
        {
          slotid = cache_alloc (sector);
          cache_slot_load (slotid, sector);
        }
      else
        {
          lock_release (&cache_lock);
          ASSERT (slotid >= 0 && slotid < CACHE_SIZE);
          lock_acquire (&slot[slotid].lock);
        }

      /* By this point, we have a lock on the desired slot. Now, we just need
         to make sure that it actually contains the sector we want. We also
         must make sure that it's not in the process of being evicted. */
      if (slot[slotid].sector == sector &&
          slot[slotid].new_sector == -1)
        return slotid;

      lock_release (&slot[slotid].lock);
    }
}

static void
cache_done (int slotid, bool written)
{
  slot[slotid].accessed = true;
  slot[slotid].dirty |= written;

  // TODO : Not do this.
  //cache_slot_flush (slotid, slot[slotid].sector);
  lock_release (&slot[slotid].lock);
}

void
cache_read (block_sector_t sector, void *buffer, off_t off, unsigned size)
{
  int slotid = cache_get_slot (sector);
  memcpy (buffer, block[slotid].data + off, size);
  cache_done (slotid, false);
}

/* Writes the given sector to the buffer cache (and, later, to disk). */
void
cache_write (block_sector_t sector, const void *data, off_t off, unsigned size)
{
  int slotid = cache_get_slot (sector);
  memcpy (block[slotid].data + off, data, size);
  cache_done (slotid, true);
}

/* Equivalent to writing all zeroes to the given sector. */
void
cache_zero (block_sector_t sector)
{
  int slotid = cache_get_slot (sector);
  memset (block[slotid].data, 0, BLOCK_SECTOR_SIZE);
  cache_done (slotid, true);
}
