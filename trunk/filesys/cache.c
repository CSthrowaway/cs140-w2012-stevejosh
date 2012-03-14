#include <string.h>
#include <random.h>
#include <debug.h>
#include "devices/timer.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"
#include "threads/synch.h"
#include "threads/thread.h"

#define MAX_SECTORS         (8 * 1024 * 1024 / BLOCK_SECTOR_SIZE)

/* Number of seconds to wait before flushing all cached data to disk. */
#define CACHE_DAEMON_PERIOD 10

/* Maximum number of accesses that a slot is allowed to record. Raising this
   constant means that a heavily-accessed slot will get more "second chances"
   when being considered for eviction. Hence, this makes the cache more
   efficient. On the other hand, raising the number too high could make
   eviction take a lot of CPU time. */
#define MAX_ACCESS          5

/* cache_data contains the metadata for a single cache slot. */
struct cache_data
  {
    bool dirty;
    int accesses;
    int sector;
    int new_sector;
    struct lock lock;
  };

/* Synchronization of cache_data members:

  bool dirty
    read  : cache_lock
    write : slot lock (single writer)

  accesses
    read  : cache_lock
    write : slot lock (single writer)

  sector
    read  : cache_lock
    write : slot lock (single writer)

  new_sector
    read  : cache_lock
    write : cache_lock

  NOTE : The value of new_sector acts as a lock to ensure that only one thread
         is ever waiting to evict the slot. Reads/writes are synched with
         cache_lock, so once a thread sets new_sector, others know not to touch
         it.
*/

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

/* Statistics for analyzing cache efficiency. */
static int flushes = 0;
static int cache_misses = 0;
static int cache_hits = 0;

/* Forces a cache flush every CACHE_DAEMON_PERIOD seconds, sleeps in between.
   Guarantees that data older than CACHE_DAEMON_PERIOD seconds won't be lost
   in a crash. */
static void
cache_daemon (void *aux UNUSED)
{
  while (true)
    {
      timer_ssleep (CACHE_DAEMON_PERIOD);
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
      slot[i].accesses = 0;
      lock_init (&slot[i].lock);
    }

  /* Spawn a thread for the cache daemon, which will force a buffer cache
     flush every CACHE_DAEMON_PERIOD seconds. */
  thread_create ("cache_daemon", PRI_DEFAULT, cache_daemon, NULL);
}

/* Flushes the given cache slot's data to the given sector. Marks the slot as
   clean when finished.
   NOTE : Assumes that the caller has a lock on the slot. */
static void
cache_slot_flush (int slotid, int sector)
{
  ASSERT (slotid >= 0 && slotid < CACHE_SIZE);
  ASSERT (sector >= 0 && sector < MAX_SECTORS);
  ASSERT (slot[slotid].dirty);
 
  lock_acquire (&io_lock);
  block_write (fs_device, sector, block[slotid].data);
  lock_release (&io_lock);
  
  slot[slotid].dirty = false;
}

/* Walks through the entire cache, flushing each slot in turn. */
void
cache_flush (void)
{
  int i;
  for (i = 0; i < CACHE_SIZE; ++i)
    {
      lock_acquire (&slot[i].lock);
      if (slot[i].dirty)
        cache_slot_flush (i, slot[i].sector);
      lock_release (&slot[i].lock);
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
  static int clock = -1;
  while (true)
    {
      clock = (clock + 1) % CACHE_SIZE;
      if (slot[clock].new_sector < 0)
        {
          if (slot[clock].accesses == 0)
            break;
          else
            slot[clock].accesses--;
        }
    }
  
  slot[clock].new_sector = new_sector;
  lock_release (&cache_lock);
  
  lock_acquire (&slot[clock].lock);
  if (slot[clock].dirty)
    cache_slot_flush (clock, slot[clock].sector);

  slot[clock].sector = new_sector;
  slot[clock].new_sector = -1;
  slot[clock].accesses = 0;
  return clock;
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
        {
          if (slot[slotid].accesses < MAX_ACCESS)
            slot[slotid].accesses++;
          return slotid;
        }

      lock_release (&slot[slotid].lock);
    }
}

static void
cache_done (int slotid, bool written)
{
  slot[slotid].dirty |= written;
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
