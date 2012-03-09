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

/////////////////////////////// NEW INODE /////////////////////////////
/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
  };

#define INODE_DIRECT_BLOCKS 8
#define INODE_DIRECT_SIZE (INODE_DIRECT_BLOCKS*BLOCK_SECTOR_SIZE)
#define INODE_DIRECT_END (INODE_DIRECT_BLOCKS*BLOCK_SECTOR_SIZE)
#define INODE_INDIRECT_SIZE (128*BLOCK_SECTOR_SIZE)
#define INODE_INDIRECT_END (INODE_DIRECT_END+INODE_INDIRECT_SIZE)
#define INODE_DOUBLY_INDIRECT_SIZE (INODE_INDIRECT_SIZE*128)
#define INODE_DOUBLY_INDIRECT_END (INODE_INDIRECT_END + INODE_DOUBLY_INDIRECT_SIZE)
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  off_t length; /* File size in bytes. */
  unsigned magic; /* Magic number. */
  uint32_t double_indirect; /* Block location of doubly indirect block. */
  uint32_t indirect; /* Block location of indirect block. */
  uint32_t direct[INODE_DIRECT_BLOCKS]; /* Direct blocks for the file
					    system. */
  uint32_t unused[116]; /* Not used. */
};

/* On-disk indirect or doubly indirect block full of indices. */
struct inode_disk_indirect
{
  uint32_t block[128];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
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
  cache_read(inode->sector, &inode_contents);
  if (pos < inode_contents.length)
    {
      int index = pos / BLOCK_SECTOR_SIZE;
      if (pos < INODE_DIRECT_END)
	  return inode_contents.direct[index];
      else if (pos < INODE_INDIRECT_END)
	{
	  int indirect_index = index - INODE_DIRECT_BLOCKS;
	  struct inode_disk_indirect indirect_contents;
	  cache_read(inode_contents.indirect, &indirect_contents);
	  return indirect_contents.block[indirect_index];
	}
      else if (pos < INODE_DOUBLY_INDIRECT_END)
	{
	  int doubly_indirect_index = index - INODE_DIRECT_BLOCKS - 128;
	  int index1 = doubly_indirect_index / 128;
	  int index2 = doubly_indirect_index % 128;
	  struct inode_disk_indirect doubly_indirect_contents;
	  struct inode_disk_indirect indirect_contents;
	  cache_read(inode_contents.double_indirect,
		     &doubly_indirect_contents);
	  cache_read(doubly_indirect_contents.block[index1],
		     &indirect_contents);
	  return indirect_contents.block[index2];
	}
    }
  return -1;

}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */

////////// MAJOR REFACTORING NEEDED FOR CLEANLINESS ///////////////

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
	  static char zeros[BLOCK_SECTOR_SIZE];
	  size_t i;
	  block_sector_t nextBlock;
	  for (i = 0; i < sectors; i++) 
	    {
	      // allocate new indirect blocks
	      if (i == INODE_DIRECT_BLOCKS)
		{
		  free_map_allocate (1, &nextBlock);
		  cache_write(nextBlock, zeros);
		  disk_inode->indirect = nextBlock;
		}
	      // allocate doubly indirect blocks
	      else if (i == INODE_DIRECT_BLOCKS+128)
		{
		  free_map_allocate (1, &nextBlock);		  
		  cache_write(nextBlock, zeros);
		  disk_inode->double_indirect = nextBlock;
		}
	      // allocate indirect blocks in doubly indirect
	      if ( (i-INODE_DIRECT_BLOCKS)%128 == 0)
		{
		  int doubly_indirect_index = i - INODE_DIRECT_BLOCKS - 128;
		  int index = doubly_indirect_index / 128;
		  free_map_allocate (1, &nextBlock);		  
		  cache_write(nextBlock, zeros);
		  struct inode_disk_indirect doubly_indirect_contents;  
		  cache_read(disk_inode->double_indirect, &doubly_indirect_contents);
		  doubly_indirect_contents.block[index] = nextBlock;
		  cache_write(disk_inode->double_indirect, &doubly_indirect_contents);
		}

	      // get block for direct block
	      free_map_allocate (1, &nextBlock);
	      if (i < INODE_DIRECT_BLOCKS) // Direct block
		disk_inode->direct[i] = nextBlock;
	      else if (i < INODE_DIRECT_BLOCKS + 128) // Indirect block
		{
		  struct inode_disk_indirect indirect_contents;
		  cache_read(disk_inode->indirect, &indirect_contents);
		  indirect_contents.block[i-INODE_DIRECT_BLOCKS] = nextBlock;
		  cache_write(disk_inode->indirect, &indirect_contents);
		}
	      else if (i < INODE_DIRECT_BLOCKS+128+128*128) // Doubly indirect block
		{
		  int doubly_indirect_index = i - INODE_DIRECT_BLOCKS - 128;
		  int index1 = doubly_indirect_index / 128;
		  int index2 = doubly_indirect_index % 128;
		  struct inode_disk_indirect doubly_indirect_contents;
		  struct inode_disk_indirect indirect_contents;		  
		  cache_read(disk_inode->double_indirect, &doubly_indirect_contents);
		  cache_read(doubly_indirect_contents.block[index1], &indirect_contents);
		  indirect_contents.block[index2] = nextBlock;
		  cache_write(doubly_indirect_contents.block[index1], &indirect_contents);
		  cache_write(disk_inode->double_indirect, &doubly_indirect_contents);
		}
	      cache_write (nextBlock, zeros);
	    }
          cache_write (sector, disk_inode);
	}
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
  //block_read (fs_device, inode->sector, &inode->data);
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
  uint8_t *bounce = NULL;

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

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_read (sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_read (sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

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
  uint8_t *bounce = NULL;

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

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cache_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_write (sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

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
  cache_read(inode->sector, &inode_contents);
  return inode_contents.length;
}
