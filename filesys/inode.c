#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Various counts for keeping track of multi-level block indices in inodes. */
#define INODE_L0_BLOCKS     ((BLOCK_SECTOR_SIZE / sizeof (uint32_t)) - 5)
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
  };

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                           /* File size in bytes. */
    unsigned magic;                         /* Magic number. */
    uint32_t blocks;                        /* Number of allocated blocks. */

    uint32_t l2;                            /* Sector of doubly indirect block. */
    uint32_t l1;                            /* Sector of indirect block. */
    uint32_t l0[INODE_L0_BLOCKS];           /* Direct block sectors. */
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

static void
inode_print (const struct inode_disk *inode)
{
  printf ("[%p]: %d blocks\n", inode, inode->blocks);
  int i;
  for (i = 0; i < inode->blocks; ++i)
    printf ("%d->%d ", i, block_to_sector (inode, i));
  printf ("\n");
}

static void
inode_validate (const struct inode_disk *inode)
{
  int i;
  for (i = 0; i < inode->blocks; ++i)
    {
      int sector = block_to_sector (inode, i);
      if (sector > 1000 || sector == 0)
        {
          printf ("block %d of inode %p failed: sector %d!\n", i, inode, sector);
          printf ("direct: %d l1 size: %d l1 end: %d\nl2 size: %d l2 end: %d\n",
            INODE_L0_BLOCKS, INODE_L1_BLOCKS, INODE_L1_END,
            INODE_L2_BLOCKS, INODE_L2_END);
          PANIC ("inode_validate: failed validation");
        }
    }
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  
  struct inode_disk inode_contents;
  cache_read(inode->sector, &inode_contents, 0, BLOCK_SECTOR_SIZE);
  
  if (pos < inode_contents.length)
    return block_to_sector (&inode_contents, pos / BLOCK_SECTOR_SIZE);
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  ASSERT (sizeof (struct inode_disk) == BLOCK_SECTOR_SIZE);
  list_init (&open_inodes);
}

/* Allocate a new block, zero the contents, and return the sector number. */
static block_sector_t
allocate_zeroed_block (void)
{
  block_sector_t block;
  free_map_allocate (1, &block);
  cache_zero (block);
  return block;
}

static void
inode_extend (struct inode_disk *inode)
{
  uint32_t blocks = inode->blocks;
  ASSERT (blocks < INODE_L2_END);

  if (blocks == INODE_L0_BLOCKS)
    inode->l1 = allocate_zeroed_block ();
  if (blocks == INODE_L1_END)
    inode->l2 = allocate_zeroed_block ();
  
  if (blocks < INODE_L0_BLOCKS)
    inode->l0[blocks] = allocate_zeroed_block ();
  else if (blocks < INODE_L1_END)
    {
      struct inode_disk_indirect ind;
      cache_read (inode->l1, &ind, 0, BLOCK_SECTOR_SIZE);
      ind.block[blocks - INODE_L0_BLOCKS] = allocate_zeroed_block ();
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
          ind.block[index] = allocate_zeroed_block ();
          cache_write (inode->l2, &ind, 0, BLOCK_SECTOR_SIZE);
        }

      /* Now, fetch the L1 entry and create a new block in it. Note that we will
         re-use the ind structure, since it is large and we don't want the
         kernel stack to grow too large. */
      int indirect_block = ind.block[index];
      cache_read (indirect_block, &ind, 0, BLOCK_SECTOR_SIZE);
      ind.block[offset] = allocate_zeroed_block ();
      cache_write (indirect_block, &ind, 0, BLOCK_SECTOR_SIZE);
    }

  inode->blocks++;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */

bool
inode_create (block_sector_t sector, off_t length)
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
      if (sectors > 0)
	      {
	        size_t i;
	        for (i = 0; i < sectors; i++) 
            inode_extend (disk_inode);
	      }
	    cache_write (sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
      success = true;
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

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
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

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
	  // TODO: Need to walk through direct, indirect, doubly indirect
	  // blocks to deallocate sectors
          /*free_map_release (inode->data.start,
	    bytes_to_sectors (inode->data.length)); */
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

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
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      cache_write (sector_idx, buffer + bytes_written, sector_ofs, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk inode_contents;
  cache_read(inode->sector, &inode_contents, 0, BLOCK_SECTOR_SIZE);
  return inode_contents.length;
}
