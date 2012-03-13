#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Various counts for keeping track of multi-level block indices in inodes. */
#define INODE_L0_BLOCKS     ((BLOCK_SECTOR_SIZE / sizeof (uint32_t)) - 6)
#define INODE_L1_BLOCKS     (BLOCK_SECTOR_SIZE / sizeof (uint32_t))
#define INODE_L1_END        (INODE_L0_BLOCKS + INODE_L1_BLOCKS)
#define INODE_L2_BLOCKS     (INODE_L1_BLOCKS * INODE_L1_BLOCKS)
#define INODE_L2_END        (INODE_L1_END + INODE_L2_BLOCKS)

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock lock;
  };

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                           /* File size in bytes. */
    unsigned magic;                         /* Magic number. */
    uint32_t blocks;                        /* Number of allocated blocks. */
    uint32_t status;                        /* Status bits. */
    uint32_t l2;                            /* Sector of doubly indirect block. */
    uint32_t l1;                            /* Sector of indirect block. */
    uint32_t l0[INODE_L0_BLOCKS];           /* Direct block sectors. */
  };

/* Top part of the on-disk inode, only includes metadata (no block sectors).
   This structure is useful for reading meta-information about a sector
   without having to store a large structure on the stack. This helps to avoid
   kernel stack overflow. */
struct inode_disk_meta
  {
    off_t length;                           /* File size in bytes. */
    unsigned magic;                         /* Magic number. */
    uint32_t blocks;                        /* Number of allocated blocks. */
    uint32_t status;                        /* Status bits. */
  };

/* On-disk indirect or doubly-indirect block full of indices. */
struct inode_disk_indirect
  {
    uint32_t block[INODE_L1_BLOCKS];
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* Return the element at offset "index" in the indirect block whose sector is
   given. A sort of disk "dereference" operation, so to speak. */
static int
indirect_lookup (block_sector_t sector, off_t offset)
{
  struct inode_disk_indirect ind;
  cache_read (sector, &ind, 0, BLOCK_SECTOR_SIZE);
  return ind.block[offset];
}

/* Convert the given block number of the given inode into a disk sector, taking
   into account the multi-level block hierarchy. */
static int
block_to_sector (const struct inode_disk *inode, unsigned block)
{
  ASSERT (block < INODE_L2_END);
  
  if (block < INODE_L0_BLOCKS)
    return inode->l0[block];
  else if (block < INODE_L1_END)
    return indirect_lookup (inode->l1, block - INODE_L0_BLOCKS);
  else
    {
      int l2_block =  (block - INODE_L1_END) / INODE_L1_BLOCKS;
      int l2_offset = (block - INODE_L1_END) % INODE_L1_BLOCKS;
      return indirect_lookup (indirect_lookup (inode->l2, l2_block), l2_offset);
    }
}

/* Returns the block device sector that contains byte offset POS
   within INODE. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  
  struct inode_disk in;
  cache_read(inode->sector, &in, 0, BLOCK_SECTOR_SIZE);
  ASSERT (pos < (off_t)(in.blocks * BLOCK_SECTOR_SIZE));
  return block_to_sector (&in, pos / BLOCK_SECTOR_SIZE);
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Lock for accesses to the open_inodes list. */
static struct lock open_inodes_lock;

/* Initializes the inode module. */
void
inode_init (void)
{
  ASSERT (sizeof (struct inode_disk) == BLOCK_SECTOR_SIZE);
  list_init (&open_inodes);
  lock_init (&open_inodes_lock);
}

/* Allocate a new block, zero the contents, and return the sector number. */
static int
allocate_zeroed_block (void)
{
  block_sector_t block;
  if (!free_map_allocate (1, &block))
    return -1;
  cache_zero (block);
  return block;
}

/* Acquires a lock on the given inode. Returns false if the lock is already
   owned by the calling thread. */
bool
inode_lock (struct inode *inode)
{
  if (lock_held_by_current_thread (&inode->lock))
    return false;
  lock_acquire (&inode->lock);
  return true;
}

/* Releases the given inode's lock. */
void
inode_unlock (struct inode *inode)
{
  lock_release (&inode->lock);
}

/* Allocate and append a single block to the given inode. The inode will be
   updated appropriately to support the new block, which may involve adding
   an indirect or doubly-indirect block in addition to the new data block. */
static bool
inode_extend_block (struct inode_disk *inode)
{
  uint32_t blocks = inode->blocks;
  ASSERT (blocks < INODE_L2_END);
  int new_sector;

  if (blocks == INODE_L0_BLOCKS)
    {
      if ((new_sector = allocate_zeroed_block ()) < 0) return false;
      inode->l1 = new_sector;
    }
  if (blocks == INODE_L1_END)
    {
      if ((new_sector = allocate_zeroed_block ()) < 0) return false;
      inode->l2 = new_sector;
    }

  if (blocks < INODE_L0_BLOCKS)
    {
      if ((new_sector = allocate_zeroed_block ()) < 0) return false;
      inode->l0[blocks] = new_sector;
    }
  else if (blocks < INODE_L1_END)
    {
      struct inode_disk_indirect ind;
      cache_read (inode->l1, &ind, 0, BLOCK_SECTOR_SIZE);
      if ((new_sector = allocate_zeroed_block ()) < 0) return false;
      ind.block[blocks - INODE_L0_BLOCKS] = new_sector;
      cache_write (inode->l1, &ind, 0, BLOCK_SECTOR_SIZE); 
    }
  else
    {
      int index =  (blocks - INODE_L1_END) / INODE_L1_BLOCKS;
      int offset = (blocks - INODE_L1_END) % INODE_L1_BLOCKS;
      struct inode_disk_indirect ind;
      cache_read (inode->l2, &ind, 0, BLOCK_SECTOR_SIZE);
      
      /* If this is the first block of a new L1 block, then we need to allocate
         the corresponding entry in the L2 block (since we haven't yet allocated
         a block for the L1 entry. */
      if (offset == 0)
        {
          if ((new_sector = allocate_zeroed_block ()) < 0) return false;
          ind.block[index] = new_sector;
          cache_write (inode->l2, &ind, 0, BLOCK_SECTOR_SIZE);
        }

      /* Now, fetch the L1 entry and create a new block in it. Note that we will
         re-use the ind structure, since it is large and we don't want the
         kernel stack to grow too large. */
      int indirect_block = ind.block[index];
      cache_read (indirect_block, &ind, 0, BLOCK_SECTOR_SIZE);
      if ((new_sector = allocate_zeroed_block ()) < 0) return false;
      ind.block[offset] = new_sector;
      cache_write (indirect_block, &ind, 0, BLOCK_SECTOR_SIZE);
    }

  inode->blocks++;
  return true;
}

/* Allocates enough disk sectors for the given inode to be able to hold size
   more bytes. Does NOT change the length field of the inode (for
   synchronization purposes.
   NOTE : Assumes that the caller has already acquired a lock on the given
          inode. */
static bool
inode_extend (struct inode *inode, unsigned size)
{
  struct inode_disk in;
  cache_read (inode->sector, &in, 0, BLOCK_SECTOR_SIZE);  

  int original_length = in.length;
  in.length += size;
  while ((off_t)(in.blocks * BLOCK_SECTOR_SIZE) < in.length)
    {
      if (!inode_extend_block (&in))
        return false;
    }

  /* Set the length back to what it was, we don't want to tamper with the
     inode's length field. */
  in.length = original_length;

  cache_write (inode->sector, &in, 0, BLOCK_SECTOR_SIZE);
  return true;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */

bool
inode_create (block_sector_t sector, off_t length, uint32_t status)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->status = status;
      success = true;
      if (sectors > 0)
	      {
	        size_t i;
	        for (i = 0; i < sectors; i++)
            if (!inode_extend_block (disk_inode))
              {
                success = false;
                break;
              }
	      }
	    cache_write (sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
    }
  free (disk_inode);
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  lock_acquire (&open_inodes_lock);
  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          goto done;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    goto done;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init (&inode->lock);

done:
  lock_release (&open_inodes_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    {
      inode_lock (inode);
      inode->open_cnt++;
      inode_unlock (inode);
    }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire (&open_inodes_lock);

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
      lock_release (&open_inodes_lock);
      
      /* Deallocate blocks if removed. */
      if (inode->removed)
        {
          /* walk through the inode's allocated blocks, freeing them one at
             a time. */
          struct inode_disk in;
          cache_read (inode->sector, &in, 0, BLOCK_SECTOR_SIZE);
          size_t i;
          for (i = 0; i < in.blocks; ++i)
            free_map_release (block_to_sector (&in, i), 1);
          free_map_release (inode->sector, 1);
        }

      free (inode); 
    }
  else
    lock_release (&open_inodes_lock);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode_lock (inode);
  inode->removed = true;
  inode_unlock (inode);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  /* If they're trying to read past the end of the file, we automatically
     fail to read anything. */
  if (offset >= inode_length (inode))
    return 0;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;

      if (chunk_size <= 0)
        break;
      cache_read (sector_idx, buffer + bytes_read, sector_ofs, chunk_size);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if an error occurs. */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  off_t inode_left = inode_length (inode) - offset;
  off_t grow_size = 0;
  bool locked = false;
  
  /* If we don't have enough space left to perform this write, then we need to
     lock the inode and extend it to make room. Note that we do NOT change the
     inode's length field until AFTER we have finished our write. */
  if (inode_left < size)
    {
      locked = inode_lock (inode);
      grow_size = size - inode_left;
      
      /* If we failed to extend the inode, then we'll just say that this entire
         operation failed. We've run out of disk space. */
      if (!inode_extend (inode, grow_size))
        {
          if (locked) inode_unlock (inode);
          return 0;
        }
    }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      
      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < sector_left ? size : sector_left;
      if (chunk_size <= 0)
        break;
      cache_write (sector_idx, buffer + bytes_written, sector_ofs, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  /* If we locked the inode, we should release the lock. We also need to update
     the inode's length field to reflect the extension. Note that we do this
     last so that other processes cannot see the intermediate result of the
     extension operation (it will not appear as though the file has grown until
     we change the inode's length). */
  if (grow_size > 0)
    {
      /* Note that we use dynamic memory here to prevent a kernel stack
         overflow. */
      struct inode_disk *in = malloc (sizeof (struct inode_disk));
      cache_read (inode->sector, in, 0, BLOCK_SECTOR_SIZE);
      in->length += grow_size;
      cache_write (inode->sector, in, 0, BLOCK_SECTOR_SIZE);
      if (locked) inode_unlock (inode);
      free (in);
    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode_lock (inode);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode_unlock (inode);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  inode_lock (inode);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  inode_unlock (inode);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk_meta in;
  cache_read(inode->sector, &in, 0, sizeof in);
  return in.length;
}

/* Returns the number of outstanding references to the given inode. */
int
inode_get_open_count (const struct inode *inode)
{
  return inode->open_cnt;
}

/* Gets the status attribute 'attribute' of the given inode. */
bool 
inode_get_attribute (struct inode *inode, uint32_t attribute)
{
  struct inode_disk_meta in;
  cache_read(inode->sector, &in, 0, sizeof in);
  return (in.status & attribute) != 0;
}

/* Sets the status attribute 'attribute' of the given inode to value on. */
void
inode_set_attribute (struct inode *inode, uint32_t attribute, bool on)
{
  struct inode_disk_meta in;
  cache_read(inode->sector, &in, 0, sizeof in);
  if (on) in.status |= attribute;
  else    in.status &= ~attribute;
  cache_write(inode->sector, &in, 0, sizeof in);
}

/* Returns the sector of the inode. */
int 
inode_get_inum (struct inode *inode)
{
  ASSERT (inode != NULL);
  return inode->sector;
}
