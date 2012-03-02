#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/swap.h"

#define BLOCKS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static struct block *swap_block;      /* Swap partition. */
static struct bitmap *free_blocks;    /* true == free, false == allocated. */
static struct lock swap_alloc_lock;   /* For allocating or freeing slots.*/
static struct lock swap_io_lock;      /* For reading or writing slots. */

void
swap_init (void)
{
  lock_init (&swap_alloc_lock);
  lock_init (&swap_io_lock);
  
  swap_block = block_get_role (BLOCK_SWAP);
  if (swap_block != NULL)
    {
      uint32_t page_count = block_size (swap_block) / BLOCKS_PER_PAGE;
      free_blocks = bitmap_create (page_count);
      if (free_blocks == NULL)
        PANIC ("swap_init: unable to create free block bitmap");
      bitmap_set_all (free_blocks, true);
    }
}

/* Allocates a page-sized swap slot, returning the swapid of the allocated
   slot. Panics the kernel if no such free slot exists. */
swapid_t
swap_alloc (void)
{
  ASSERT (swap_block != NULL);
  lock_acquire (&swap_alloc_lock);
  size_t id = bitmap_scan_and_flip (free_blocks, 0, 1, true);
  if (id == BITMAP_ERROR)
    PANIC ("swap_alloc: out of swap space");

  lock_release (&swap_alloc_lock);
  return id;
}

/* Frees the swap slot associated with the given swapid. */
void
swap_free (swapid_t id)
{
  ASSERT (swap_block != NULL);
  ASSERT (id < bitmap_size (free_blocks));

  lock_acquire (&swap_alloc_lock);
  bitmap_set (free_blocks, id, true);
  lock_release (&swap_alloc_lock);
}

/* Reads a page of data from the given swap slot.
   NOTE : buf MUST be *at least* PGSIZE bytes! */
void
swap_read (swapid_t id, char *buf)
{
  ASSERT (swap_block != NULL);
  lock_acquire (&swap_io_lock);
  int i;
  for (i = 0; i < BLOCKS_PER_PAGE; ++i)
    {
      block_read (swap_block, id * BLOCKS_PER_PAGE + i, buf);
      buf += BLOCK_SECTOR_SIZE;
    }
  lock_release (&swap_io_lock);
}

/* Writes a page of data to the given swap slot.
   NOTE : buf must be *at least* PGSIZE bytes! */
void
swap_write (swapid_t id, const char *buf)
{
  ASSERT (swap_block != NULL);
  lock_acquire (&swap_io_lock);
  int i;
  for (i = 0; i < BLOCKS_PER_PAGE; ++i)
    {
      block_write (swap_block, id * BLOCKS_PER_PAGE + i, buf);
      buf += BLOCK_SECTOR_SIZE;
    }
  lock_release (&swap_io_lock);
}
