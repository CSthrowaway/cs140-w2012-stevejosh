#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device = NULL;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Returns whether or not the filesystem has been initialized. */
bool
filesys_initialized (void)
{
  return fs_device != NULL;
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
  cache_flush ();
  free_map_close ();
}

/* Splits the given path into the parent directory and the file name. Returns
   the sector of the parent directory and stores the file name in "element". */
static int
filesys_split_path (const char *path, char *element)
{
  const char *last_slash = strrchr (path, '/');
  if (last_slash == NULL)
    {
      strlcpy (element, path, NAME_MAX + 1);
      return thread_current ()->cwd;
    }
  else
    {
      char partial_path[FILE_PATH_MAX + 1];
      strlcpy (partial_path, path, last_slash - path + 2);
      strlcpy (element, last_slash + 1, NAME_MAX + 1);
      return filesys_lookup (partial_path);
    }
}

/* Checks that the given name is actually a valid filesystem name. To do so,
   we simply check that each component of the name is <= NAME_MAX in length. */
static bool
filesys_name_valid (const char *name)
{
  size_t token_length = 0;
  char c;
  for (; (c = *name) != '\0'; name++)
    {
      token_length++;
      if (c == '/') token_length = 0;
      if (token_length > NAME_MAX)
        return false;
    }
  return true;
}

static bool
filesys_do_create (const char *name, off_t initial_size, bool is_dir)
{
  /* Check to make sure that this is a valid name. */
  if (!filesys_name_valid (name))
    return false;

  bool locked = false;
  block_sector_t inode_sector = 0;
  struct file *self = NULL;
  
  if (!free_map_allocate (1, &inode_sector))
    return false;
  
  /* Try to create the inode. */
  uint32_t inode_flags = is_dir ? INODE_DIR : 0;
  if (!(inode_create (inode_sector, initial_size, inode_flags)))
    goto failed;

  char name_short[NAME_MAX + 1];
  int parent_sector = filesys_split_path (name, name_short);

  if (parent_sector < 0) return false;
  
  self = file_open (inode_open (inode_sector));
  if (self == NULL) goto failed;

  /* Acquire a lock on the file we're creating so that no one can access it
     while we're in the process of creating it (this is particularly
     important for directories, which cannot be accessed until we create the
     "." and ".." entries). */
  locked = file_lock (self);
  ASSERT (locked);
  
  struct file *parent = file_open (inode_open (parent_sector));
  if (parent == NULL) goto failed;

  /* Make sure that the parent is actually a directory, then try to add the new
     file to the parent's directory listing. */
  if (!file_is_dir (parent) ||
      !dir_add (parent, name_short, inode_sector))
    {
      file_close (parent);
      goto failed;
    }
  file_close (parent);

  /* If we're creating a directory, then we need to populate it with the "."
     and ".." entries. */
  if (is_dir)
    {
      dir_add (self, ".", inode_sector);
      dir_add (self, "..", parent_sector);
    }
    
  /* Finally, release the lock and close this file. */
  file_unlock (self);
  file_close (self);
  return true;

failed:
  if (locked) file_unlock (self);
  if (self)   file_close (self);
  free_map_release (inode_sector, 1);
  return false;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  return filesys_do_create (name, initial_size, false);
}

/* Creates a directory named NAME. Returns success. */
bool
filesys_create_dir (const char *name)
{
  return filesys_do_create (name, 0, true);
}

/* Looks up the given file path, starting in the directory whose sector is
   given. Returns the sector of the file if found, or -1 if the path does not
   match an existing file/directory. */
static int
filesys_lookup_recursive (const char *path, block_sector_t sector)
{
  size_t len = strlen (path);
  char buf [len + 1];
  char *cpath = buf;
  strlcpy (buf, path, len + 1);

  while (true)
    {
      len = strlen (cpath);      

      /* If the length of the path is zero, it means that we've found what we
         were looking for! */
      if (len == 0) return sector;

      /* Chop off leading forward slashes. */
      if (cpath[0] == '/')
        {
          cpath++;
          continue;
        }
      
      /* Chop off trailing forward slashes. */
      if (cpath[len - 1] == '/')
        {
          cpath[len - 1] = '\0';
          continue;
        }

      /* Determine the first component of the path. */
      size_t next_slash = strcspn (cpath, "/");
      char lookup_buf [next_slash + 1];
      strlcpy (lookup_buf, cpath, next_slash + 1);
      
      /* Open the parent directory and look for the component. */
      struct file *dir = file_open (inode_open (sector));

      /* Make sure that the parent is actually a directory. */
      if (!file_is_dir (dir))
        {
          file_close (dir);
          return -1;
        }

      /* Search for the component in the parent directory. */
      file_lock (dir);
      int next_sector = dir_lookup (dir, lookup_buf);
      file_unlock (dir);
      file_close (dir);

      /* If we couldn't find it, then return -1. Otherwise, continue the
         lookup by advancing the cpath pointer to the next component and
         modifying the sector to reflect the new sector that we just found. */

      if (next_sector < 0)
        return -1;
      else
        {
          cpath += next_slash;
          sector = next_sector;
          continue;
        }
    }
}

/* Looks up NAME in the file system, returning the disk sector associated with
   NAME's inode, or -1 if no such file or directory exists in the file system.
   Makes use of the thread's current working directory if a relative path is
   given. */
int
filesys_lookup (const char *name)
{
  int len = strlen (name);
  if (len == 0)
    return -1;

  int sector;
  /* If the name starts with a forward slash, then use the root directory as
     the base for the lookup. Otherwise, use the current thread's cwd. */
  if (name[0] == '/')
    sector = filesys_lookup_recursive (name, ROOT_DIR_SECTOR);
  else
    sector = filesys_lookup_recursive (name, thread_current ()->cwd);
  return sector;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  int sector = filesys_lookup (name);
  if (sector < 0)
    return NULL;
  else
    return file_open (inode_open (sector));
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char name_short[NAME_MAX + 1];
  int parent_sector = filesys_split_path (name, name_short);
  
  if (parent_sector < 0)
    return false;

  struct file *file = filesys_open (name);
  if (file == NULL)
    return false;
  
  if (file_is_dir (file))
    {
      /* If the dir's inode is open, we won't allow deletion of it. */
      int opencnt = inode_get_open_count (file->inode);
      if (opencnt > 1)
        {
          file_close (file);
          return false;
        }
      
      /* If the dir is not empty, we won't allow deletion of it. */
      if (!dir_is_empty (file))
        {
          file_close (file);
          return false;
        }
    }
  file_close (file);

  struct file *parent = file_open (inode_open (parent_sector));
  ASSERT (parent != NULL);
  
  bool success = false;
  if (dir_remove (parent, name_short))
    success = true;
  file_close (parent);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  struct file *root;
  
  if (!dir_create (ROOT_DIR_SECTOR, 0) ||
      !(root = file_open (inode_open (ROOT_DIR_SECTOR))) ||
      !dir_add (root, ".", ROOT_DIR_SECTOR) ||
      !dir_add (root, "..", ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");

  file_close (root);
  free_map_close ();
  printf ("done.\n");
}
