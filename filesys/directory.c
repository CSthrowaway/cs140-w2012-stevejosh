#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry),
                       INODE_DIR);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
static struct file *
dir_open (struct inode *inode) 
{
  ASSERT (inode != NULL);
  
  if (!inode_get_attribute (inode, INODE_DIR))
    return NULL;
    
  return file_open (inode);
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct file *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct file *dir) 
{
  return dir->inode;
}

/* Finds the next element of the given directory and stores the element's name
   in the given buffer. Returns true if an element was found, false if not.
   Note that "." and ".." are not considered true elements, and will never be
   returned by this function. */
bool
dir_readdir (struct file *dir, char *buf)
{
  /* If the cursor is before the third entry, then it's pointing at "." or "..",
     since there are *always* the first two directory entries. Seek to beyond
     them, since we don't want to return them. */
  off_t min_cursor = 2 * sizeof (struct dir_entry);
  if (file_tell (dir) < min_cursor)
    file_seek (dir, min_cursor);

  // TODO : Synch
  while (true)
    {
      struct dir_entry e;
      if (file_read (dir, &e, sizeof e) != sizeof e)
        return false;
      if (e.in_use)
        {
          strlcpy (buf, e.name, NAME_MAX + 1);
          return true;
        }
    }
}

static int
lookup (struct file *dir, const char *name, off_t *out_ofs,
        struct dir_entry *out_entry)
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (name != NULL);
  
  int return_value = -1;

  // TODO lock?
  size_t dir_size = inode_length (dir->inode);
  //printf ("Scanning dir %d (%d entries) for %s.\n", inode_get_inumber (dir->inode), dir_size / sizeof(e), name);
  for (ofs = 0; ofs < dir_size; ofs += sizeof e) 
    {
      inode_read_at (dir->inode, &e, sizeof e, ofs);
      //printf ("\t%s match?\n", e.name);
      if (e.in_use && !strcmp (name, e.name))
        {
          if (out_ofs)    *out_ofs = ofs;
          if (out_entry)  *out_entry = e;
          return_value = e.inode_sector;
          break;
        }
    }
  return return_value;
}

int
dir_lookup (struct file *dir, const char *name)
{
  return lookup (dir, name, NULL, NULL);
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct file *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  size_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (dir_lookup (dir, name) >= 0)
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  // TODO Synch
  size_t dir_size = inode_length (dir->inode);
  for (ofs = 0; ofs < dir_size; ofs += sizeof e) 
    {
      inode_read_at (dir->inode, &e, sizeof e, ofs);
      if (!e.in_use)
        break;
    }

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct file *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;
  block_sector_t sector;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!(sector = lookup (dir, name, &ofs, &e)))
    goto done;

  /* Open inode. */
  inode = inode_open (sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}
