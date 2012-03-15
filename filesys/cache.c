#include <string.h>
#include <random.h>
#include <debug.h>
#include "devices/timer.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* Number of milliseconds to wait before flushing all cached data to disk. */
#define CACHE_DAEMON_PERIOD 1000

/* Maximum size of the read-ahead queue. If the queue grows larger than this,
   old requests will be discarded and replaced by new ones (the old ones
   wouldn't be of use anyway, since they would be evicted by new requests
   before having a chance to get used). */
#define RA_QUEUE_SIZE CACHE_SIZE

/* Maximum number of accesses that a slot is allowed to record. Raising this
   constant means that a heavily-accessed slot will get more "second chances"
   when being considered for eviction. Hence, this makes the cache more
   efficient. On the other hand, raising the number too high could make
   eviction take a lot of CPU time. */
#define MAX_ACCESS          5

/* cache_data contains the metadata for a single cache slot. */
struct cache_data
  {
    bool dirty;       /* Whether the slot has been written to. */
    int accesses;     /* How many times the slot has been accessed. */
    int sector;       /* The disk sector to which this slot corresponds. */
    int new_sector;   /* If the slot is being evicted, the sector that will
                         replace the current one after eviction. -1 if the
                         slot is not being evicted. */
    struct lock lock; /* Lock for synchronizing access to the slot. */
  };

/* cache_block provides a convenient way to declare and access
   BLOCK_SECTOR_SIZE chunks of data. */
struct cache_block
  {
    char data[BLOCK_SECTOR_SIZE];
  };

static struct lock cache_lock;                /* Cache metadata lock. */
static struct lock io_lock;                   /* Block device lock. */
static struct cache_data slot[CACHE_SIZE];    /* Cache slot metadata. */
static struct cache_block block[CACHE_SIZE];  /* Cache slot buffers. */

static struct lock ra_lock;                   /* Read-ahead queue lock. */
static struct condition ra_cond;              /* Read-ahead condition variable
                                                 for waking daemon. */
static int ra_queue[RA_QUEUE_SIZE];           /* Read-ahead queue. */
static int ra_queue_counter = 0;              /* Read-ahead queue position. */

static void cache_done (int slotid, bool written);
static int cache_get_slot (int sector);

/* Write-behind cache daemon: forces a cache flush every CACHE_DAEMON_PERIOD
   seconds, sleeps in between. Guarantees that data older than
   CACHE_DAEMON_PERIOD milliseconds won't be lost in a crash. */
static void
cache_daemon_wb (void *aux UNUSED)
{
  while (true)
    {
      timer_msleep (CACHE_DAEMON_PERIOD);
      cache_flush ();
    }
}

/* Read-ahead cache daemon: services read-ahead requests, allowing precaching
   of disk sectors before they get used. Ideally, improves performance by
   reducing I/O time for processes. */
static void
cache_daemon_ra (void *aux UNUSED)
{
  int queue_pos = 0;
  while (true)
    {
      lock_acquire (&ra_lock);
      
      /* Wait for requests to come in. */
      while (queue_pos == ra_queue_counter)
        cond_wait (&ra_cond, &ra_lock);

      /* Retrieve the sector of the next request. */
      int queue_cur = queue_pos % RA_QUEUE_SIZE;
      int sector = ra_queue[queue_cur];
      ASSERT (sector >= 0);
      
      /* Now we can release the lock, since we've pulled the sector number. */
      lock_release (&ra_lock);
      
      /* Service the request and increment our own queue counter. */
      int slotid = cache_get_slot (sector);
      cache_done (slotid, false);
      queue_pos++;
    }
}

void
cache_init (void)
{
  lock_init (&cache_lock);
  lock_init (&io_lock);
  lock_init (&ra_lock);
  cond_init (&ra_cond);

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

  for (i = 0; i < RA_QUEUE_SIZE; ++i)
    ra_queue[i] = -1;

  /* Spawn a thread for the cache daemons, which will implement write-behind
     and read-ahead. */
  thread_create ("cached_wb", PRI_DEFAULT, cache_daemon_wb, NULL);
  thread_create ("cached_ra", PRI_DEFAULT, cache_daemon_ra, NULL);
}

/* Flushes the given cache slot's data to the given sector. Marks the slot as
   clean when finished.
   NOTE : Assumes that the caller has a lock on the slot. */
static void
cache_slot_flush (int slotid, int sector)
{
  ASSERT (lock_held_by_current_thread (&slot[slotid].lock));
  ASSERT (slotid >= 0 && slotid < CACHE_SIZE);
  ASSERT (sector >= 0);
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
  ASSERT (lock_held_by_current_thread (&slot[slotid].lock));
  ASSERT (slotid >= 0 && slotid < CACHE_SIZE);
  ASSERT (sector >= 0);
  
  lock_acquire (&io_lock);
  block_read (fs_device, sector, block[slotid].data);
  lock_release (&io_lock);
}

static int
cache_alloc (int new_sector)
{
  ASSERT (lock_held_by_current_thread (&cache_lock));

  int evict;
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
    
    /* Store the eviction index, since clock is subject to change as soon as we
       release the cache_lock. */
    evict = clock;
  }

  /* Once we mark the slot as in the process of eviction, we are free to
     release the cache lock, since no other thread will try to evict this
     slot. */
  slot[evict].new_sector = new_sector;
  lock_release (&cache_lock);
  
  /* Now, we need to acquire a lock on the slot we wish to evict. */
  lock_acquire (&slot[evict].lock);

  /* If it's dirty, we'll need to flush the slot to disk. */
  if (slot[evict].dirty)
    cache_slot_flush (evict, slot[evict].sector);

  /* Clear the slot's metadata. */
  slot[evict].sector = new_sector;
  slot[evict].new_sector = -1;
  slot[evict].accesses = 0;
  return evict;
}

/* Finds the buffer cache slot corresponding to the given sector. If such a
   slot does not exist, this will allocate a new slot, forcing the eviction of
   an older sector if necessary. Returns the slot id of a slot that now (at the
   time of returning) corresponds to the given sector. When this returns, the
   caller will own the lock on the returned slot. */
static int
cache_get_slot (int sector)
{
  ASSERT (sector >= 0);

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
      
      /* If we were unable to find a slot corresponding to this sector, we'll
         have to allocate a new one. */
      if (slotid < 0)
        {
          slotid = cache_alloc (sector);
          ASSERT (slotid >= 0 && slotid < CACHE_SIZE);
          ASSERT (lock_held_by_current_thread (&slot[slotid].lock));
          cache_slot_load (slotid, sector);
        }
      /* Otherwise, we can just acquire a lock on the existing one. */
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

      /* If we failed, we'll have to try again. */
      lock_release (&slot[slotid].lock);
    }
}

/* Releases the lock on the given slot, as well as modifies the dirty bit if
   necessary. */
static void
cache_done (int slotid, bool written)
{
  slot[slotid].dirty |= written;
  lock_release (&slot[slotid].lock);
}

/* Submits a read-ahead request for the given sector. */
static void
cache_ra_request (block_sector_t sector)
{
  /* Make sure this request isn't beyond the maximal sector. */
  if (sector >= block_size (fs_device)) return;

  lock_acquire (&ra_lock);

  /* Set an element of the queue and increment the queue counter. */ 
  ra_queue[ra_queue_counter % RA_QUEUE_SIZE] = sector;
  ra_queue_counter++;
  
  /* Signal the read-ahead daemon that there's a new request. */
  cond_signal (&ra_cond, &ra_lock);
  lock_release (&ra_lock);
}

/* Reads the given sector from the buffer cache. */
void
cache_read (block_sector_t sector, void *buffer, off_t off, unsigned size)
{
  int slotid = cache_get_slot (sector);
  memcpy (buffer, block[slotid].data + off, size);
  cache_done (slotid, false);
  
  /* Submit a read-ahead request for the next sector. */
  cache_ra_request (sector + 1);
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
