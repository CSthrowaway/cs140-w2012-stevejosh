#include "devices/input.h"
#include "lib/kernel/hash.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "vm/swap.h"

/* Split calls to putbuf up into chunks of PUTBUF_BLOCK_SIZE
   bytes each. */
#define PUTBUF_BLOCK_SIZE 128

static void syscall_handler (struct intr_frame *);

static unsigned filesys_fdhash_func (const struct hash_elem *e,
                                     void *aux);
static unsigned filesys_fileref_func (const struct hash_elem *e,
                                      void *aux);

static bool filesys_fdhash_less (const struct hash_elem *a,
                                 const struct hash_elem *b,
                                 void *aux UNUSED);
static bool filesys_fileref_less (const struct hash_elem *a,
                                    const struct hash_elem *b,
                                    void *aux UNUSED);
static struct file* filesys_get_file (int fd);

static struct lock filesys_lock;    /* Lock for file system access. */
static struct hash filesys_fdhash;  /* Hash table mapping fds to
                                       struct file*s. */
static struct hash filesys_fileref; /* Hash table for counting number of
                                       open handles to a file and
                                       whether it's been marked for
                                       deletion. */

/* Gives the number of arguments expected for a given system
   call number. Useful to unify the argument-parsing code in
   syscall_handler. */
static uint8_t syscall_arg_count[] =
{
  0,      /* Halt */
  1,      /* Exit */
  1,      /* Exec */
  1,      /* Wait */
  2,      /* Create */
  1,      /* Remove */
  1,      /* Open */
  1,      /* FileSize */
  3,      /* Read */
  3,      /* Write */
  2,      /* Seek */
  1,      /* Tell */
  1,      /* Close */
  2,      /* Mmap */
  1       /* Munmap */
};

/* An fd_elem encapsulates the information held by a file descriptor.
   The fd_elem is inserted into the filesys_fdhash table upon creation
   of the fd, and is used to keep track of file information. The fd_elem
   is also attached to the creating thread's open_files list. This is
   the central element for file resource tracking. */
struct fd_elem
{
  struct hash_elem h_elem;          /* Element hash table insertion. */
  struct list_elem l_elem;          /* Element for list insertion. */
  int fd;                           /* Associated fd number. */
  int owner_pid;                    /* pid of the owning process. */
  struct file *file;                /* File system file handle. */
};

/* A fileref_elem encapsulates information about a particular file's
   reference count - that is, how many outstanding FDs reference
   the file. It also indicates whether the file is marked for deletion
   or not. */
struct fileref_elem
{
  struct hash_elem h_elem;          /* Element hash table insertion. */
  int inumber;                      /* inode number specifying the
                                       file. */
  int count;                        /* Number of existing references to
                                       this file. */
  bool delete;                      /* Whether the file has been marked
                                       for deleteion by a previous remove
                                       system call. */
  char name[NAME_MAX + 1];          /* Name of the file. */
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
  hash_init (&filesys_fdhash,
             filesys_fdhash_func,
             filesys_fdhash_less, NULL);
  hash_init (&filesys_fileref,
             filesys_fileref_func,
             filesys_fileref_less, NULL);
  process_init ();
  frame_init ();
}

/* Hash function for fd_elems. */
static unsigned
filesys_fdhash_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct fd_elem *elem = hash_entry(e, struct fd_elem, h_elem);
  return (unsigned)elem->fd;
}

/* Hash function for fileref_elems. */
static unsigned
filesys_fileref_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct fileref_elem *elem = hash_entry(e, struct fileref_elem, h_elem);
  return (unsigned)elem->inumber;
}

/* Comparator for fd_elems. */
static bool
filesys_fdhash_less (const struct hash_elem *a,
                     const struct hash_elem *b,
                     void *aux UNUSED)
{
  struct fd_elem *a_e = hash_entry(a, struct fd_elem, h_elem);
  struct fd_elem *b_e = hash_entry(b, struct fd_elem, h_elem);
  return (a_e->fd < b_e->fd);
}

/* Comparator for fd_elems. */
static bool
filesys_fileref_less (const struct hash_elem *a,
                        const struct hash_elem *b,
                        void *aux UNUSED)
{
  struct fileref_elem *a_e = hash_entry (a, struct fileref_elem, h_elem);
  struct fileref_elem *b_e = hash_entry (b, struct fileref_elem, h_elem);
  return (a_e->inumber < b_e->inumber);
}

/* Acquires the file system lock. */
static void
lock_filesys (void)
{
  lock_acquire (&filesys_lock);
}

/* Releases the file system lock. */
static void
unlock_filesys (void)
{
  lock_release (&filesys_lock);
}

/* Return the fd_elem (stored in the global fd hash table) associated
   with the given fd number. Returns NULL if the given fd does not
   exist. */
static struct fd_elem*
filesys_get_fdelem (int fd)
{
  struct fd_elem search;
  search.fd = fd;

  struct hash_elem *found;
  found = hash_find (&filesys_fdhash, &search.h_elem);

  if (found == NULL)
    return NULL;

  struct fd_elem *fd_elem = hash_entry (found, struct fd_elem, h_elem);

  /* If we found a valid fd but the pid on it doesn't match our tid,
     this function must pretend like it didn't find anything, because
     we shouldn't have access to someone else's fd. */
  return (thread_current ()->tid == fd_elem->owner_pid) ? fd_elem : NULL;
}

/* Returns the fileref_elem (stored in the global fileref hash table)
   associated with the given inode*. Returns NULL if not found. */
static struct fileref_elem*
filesys_get_fileref_from_inode (struct inode* i)
{
  struct fileref_elem search;
  search.inumber = inode_get_inumber (i);

  struct hash_elem *found;
  found = hash_find (&filesys_fileref, &search.h_elem);

  if (found == NULL)
    return NULL;

  struct fileref_elem *fileref_hash_entry =
    hash_entry (found, struct fileref_elem, h_elem);
  return fileref_hash_entry;
}

/* Returns the fileref_elem (stored in the global fileref hash table)
   associated with the given file*. Returns NULL if not found. */
static struct fileref_elem*
filesys_get_fileref (struct file* f)
{
  return filesys_get_fileref_from_inode (file_get_inode (f));
}

/* Returns the fileref_elem name member of the file corresponding to the
   given file descriptor fd. */
const char*
filesys_get_filename_from_fd (int fd)
{
  struct file* f = filesys_get_file (fd);
  if (f != NULL)
    return (filesys_get_fileref (f))->name;
  else
    return NULL;
}

/* Closes the given file. In doing so, properly decrements the global
   reference count associated with the file, removing it if necessary. */
static void
filesys_close_file (struct file* f)
{
  struct fileref_elem* fileref = filesys_get_fileref(f);
  ASSERT(fileref != NULL);
  fileref->count--;

  /* If we hold the last reference to this file, then we are responsible
     for cleaning up the reference as well as removing the file if
     necessary. */
  if (fileref->count == 0)
    {
      hash_delete (&filesys_fileref, &fileref->h_elem);

      /* If the file reference indicates that the file must be deleted,
         then we must do so, using the filename stored in the reference.
         Otherwise, we just close the file as normal. */
      if (fileref->delete)
        filesys_remove (fileref->name);
      else
        file_close (f);
      free (fileref);
    }
    
  /* If others are still holding references to this file, we don't have
     to worry about removing the reference; we just close the file. */
  else
    file_close (f);
}

/* Frees the resources associated with the given file descriptor
   element. This includes removing it from the global fd hash table,
   removing it from the owning thread's fd list, and freeing the
   associated memory. */
static void
filesys_free_fdelem (struct fd_elem *elem)
{
  filesys_close_file (elem->file);
  hash_delete (&filesys_fdhash, &elem->h_elem);
  list_remove (&elem->l_elem);
  free (elem);
}

/* Return the file struct associated with the given fd number, or
   NULL if the given fd does not exist. */
static struct file*
filesys_get_file (int fd)
{
  struct fd_elem *found = filesys_get_fdelem (fd);
  return found != NULL ? found->file : NULL;
}

void
filesys_free_open_files (struct thread *t)
{
  lock_filesys ();
  struct list_elem *e;
  for (e = list_begin (&t->open_files); e != list_end (&t->open_files);)
    {
      /* We need to save the next ptr, since we're about to delete e's
         host memory. */
      struct list_elem *next = list_next (e);
      struct fd_elem *fd_elem = list_entry (e, struct fd_elem, l_elem);
      filesys_free_fdelem (fd_elem);
      e = next;
    }

  unlock_filesys ();
}

/* Return an integer >= 2 that is unique for the life of the kernel.
   NOTE : Assumes that the filesystem lock has already bee acquired! */
static int
allocate_fd (void)
{
  static int fd_current = 2;
  return fd_current++;
}

/* Attempts to translate the given virtual address into a physical address,
   returning NULL if the virtual memory has not yet been mapped. */
static const void*
translate_vaddr (const void *vaddr)
{
  if (!is_user_vaddr (vaddr))
    return NULL;
  return pagedir_get_page (thread_current ()->pagedir, vaddr);
}

/* Checks the supposed string in user memory at the given location, making
   sure that the string is safe to read. Additionally, checks to make sure
   that the string is <= max_length in size. If the string is unsafe,
   returns -1. If the string is too big, returns max_length + 1. Otherwise,
   returns the length of the (safe) string. */
static int
validate_str (const char *vstr, int max_length)
{
  int i;
  for (i = 0; i <= max_length; ++i)
  {
    const char *c = translate_vaddr (vstr++);
    if (c == NULL)
      return -1;
    if (*c == '\0')
      return i;
  }
  
  return max_length + 1;
}

/* Checks that the given buffer is entirely valid virtual memory. If the
   buffer is valid, returns the physical address of the buffer. Otherwise,
   returns NULL. Additionally, will return NULL if writable is true and any
   part of the buffer is marked as read-only in virtual memory. */
static const void*
validate_buffer (const char *buffer, unsigned size)
{
  if (size == 0) return buffer;

  struct page_table *pt = thread_current ()->page_table;
  struct page_table_entry *pte;

  /* Try to translate the first address of the buffer. If this fails, we
     know it's a bad buffer. */
  pte = page_table_lookup (pt, (const void *)buffer);
  if (pte == NULL)
    return NULL;

  const char *next = buffer;

  /* Now, check that every page between the beginning and the end of the
     buffer is actually mapped into memory. Otherwise, a clever user could
     potentially make us crash by giving us a buffer that appears to exist
     at both ends but has gaps in it (e.g., take an address in the code
     segment and add a size that reaches up to the stack...) */
  unsigned i;
  for (i = 0; i < size; i += PGSIZE)
    {
      unsigned offset = (size - i - 1);
      next += (offset < PGSIZE) ? offset : PGSIZE;
      pte = page_table_lookup (pt, (const void *)next);
      if (pte == NULL)
      page_table_entry_load (page_table_lookup (pt, (const void *)next));
    }

  // TODO TODO TODO TODO TODO TODO REMOVE THIS HACK (page_table_entry_load);
  
  /* Looks like the whole buffer exists, so we can return the trnaslated
     beginning pointer. */
  page_table_entry_load (page_table_lookup (pt, (const void *)buffer));
  return buffer;
}

static bool
begin_page_operation (const char *buffer, bool writable)
{
  if (buffer >= PHYS_BASE) return false;
  struct page_table *pt = thread_current ()->page_table;
  struct page_table_entry *pte = page_table_lookup (pt, buffer);
  if (pte == NULL)
    {
      /* If this is meant to be a writable page, then perhaps we could extend
         the stack to bring it into existence. If that's the case, we'll
         succeed below, and the page will exist. Otherwise, we'll get killed
         by the fault-handler, which is what we want anyway (because the access
         is invalid in that case). */
      if (writable)
        {
          *(char *)buffer = 0x8D;
          pte = page_table_lookup (pt, buffer);
          ASSERT (pte != NULL);
        }
      else
        return false;
    }
  if (writable && (pte->frame->status & FRAME_READONLY)) return false;

  pte->frame->status |= FRAME_PINNED;
  page_table_entry_load (pte);
  ASSERT (pte->frame->paddr != NULL);
  return true;
}

static void
end_page_operation (const char *buffer)
{
  struct page_table *pt = thread_current ()->page_table;
  struct page_table_entry *pte = page_table_lookup (pt, buffer);
  pte->frame->status &= (~FRAME_PINNED);
}

/* -- System Call #0 --
   Shuts off the OS. */
static void
syscall_halt (void)
{
  shutdown_power_off();
}

/* -- System Call #1 --
   Exits the current thread, releasing any resources that the kernel
   acquired on behalf of the thread. */
static void
syscall_exit (int code)
{
  process_release (code);
  thread_exit ();
}

/* Returns true if the given (user-space) string is a valid filename, and
   false if it is not. Kills the process if the string is found to contain
   invalid memory. */
static bool
is_valid_filename (const char* file)
{
  int name_size;
  /* If the user process gives us a bad pointer, kill it. */
  if (file == NULL)
    syscall_exit (-1);
  name_size = validate_str (file, NAME_MAX);
  if (name_size == -1)
    syscall_exit(-1);
  return name_size <= NAME_MAX;
}

/* -- System Call #2 --
   Executes the given command line, returning the child process' pid, or
   -1 if the child process fails to load or run for some reason. */
static pid_t
syscall_exec (const char *cmd_line)
{
  int cmd_line_size;
  if ((cmd_line_size = validate_str (cmd_line, PGSIZE)) == -1)
    syscall_exit (-1);

  if (cmd_line_size > PGSIZE)
    return TID_ERROR;

  tid_t tid = process_execute (cmd_line);
  return tid == TID_ERROR ? -1 : tid;
}

/* -- System Call #3 --
   Waits for the given child process to exit, returning the exit code
   when the process exits. Returns -1 in the event that the pid is
   invalid, or that the process doesn't exist as a child of the current
   one, or that the kernel killed the child process. */
static int
syscall_wait (pid_t pid)
{
  return process_wait (pid);
}

/* -- System Call #4 --
   Creates a new file initially initial_size in bytes. Returns true if
   successful, false otherwise. Does not open the new file. */
static bool
syscall_create (const char *file, unsigned initial_size)
{
  if (!is_valid_filename (file))
    return false;

  lock_filesys ();
  bool success = filesys_create (file, initial_size);
  unlock_filesys ();
  return success;
}

/* -- System Call #5 --
   Deletes the file called file. Returns true if successful, false
   otherwise. A file can be removed whether it is opened or closed. If it
   is still opened (file descriptor exists referring to it), the file can
   still be read and write from, but it no longer has a name and no one
   else can open it. */
static bool
syscall_remove (const char *file)
{
  if (!is_valid_filename (file))
    return false;

  struct inode* inode;
  lock_filesys ();

  bool success;
  struct fileref_elem* fileref;

  /* Make sure the file exists. */
  if (dir_lookup (dir_open_root (), file, &inode))
    {
      /* Retrieve the fileref entry for this file. If the file is
         currently opened by other processes, we must mark it for
         deletion. Otherwise, we can go ahead and delete it. */
      fileref = filesys_get_fileref_from_inode(inode);

      if (fileref == NULL)
        success = filesys_remove (file);
      else if (fileref->count == 0)
        {
          hash_delete (&filesys_fileref, &fileref->h_elem);
          success = filesys_remove (file);
          free (fileref);
        }
      else
          fileref->delete = true;
      success = true;
    }
  else
      success = false;

  inode_close (inode);
  unlock_filesys ();
  return success;
}

int
fd_open (const char *file)
{
  lock_filesys ();
  struct file* handle = filesys_open (file);
  
  if (handle == NULL)
    {
      unlock_filesys ();
      return -1;
    }

  struct fd_elem *newhash = malloc (sizeof(struct fd_elem));

  /* If malloc failed, we need to clean up and return an error code. */
  if (newhash == NULL)
    {
      file_close (handle);
      unlock_filesys ();
      return -1;
    }
  
  struct fileref_elem* fileref = filesys_get_fileref(handle);

  /* If the file doesn't already exist in the reference table, then we must
     create a new reference count for it and set the count to 1. Otherwise,
     we simply increment the existing reference count. */
  if (fileref == NULL)
    {
      fileref = malloc (sizeof (struct fileref_elem));

      /* If malloc failed, clean up and return an error code. */
      if (fileref == NULL)
        {
          free (newhash);
          file_close (handle);
          unlock_filesys ();
          return -1;
        }
      
      fileref->inumber = inode_get_inumber (file_get_inode (handle));
      fileref->count = 1;
      fileref->delete = false;
      strlcpy (fileref->name, file, NAME_MAX + 1);
      hash_insert (&filesys_fileref, &fileref->h_elem);
    }
  else {
    /* If the file has already been marked for deletion, we shouldn't let
       anyone else open it, even though it still exists. */
    if (fileref->delete)
      {
        file_close (handle);
        unlock_filesys ();
        return -1;
      }

    fileref->count++;
  }

  /* Initialize and insert the fd only after we know that the fileref
     operations have succeeded. */
  newhash->fd = allocate_fd ();
  newhash->file = handle;
  newhash->owner_pid = thread_current ()->tid;
  hash_insert (&filesys_fdhash, &newhash->h_elem);
  list_push_back (&thread_current ()->open_files, &newhash->l_elem);

  unlock_filesys ();
  return newhash->fd;
}

/* -- System Call #6 --
   Opens a file called file. Returns a nonnegative file descriptor that is
   globally unique, or -1 if the file could not be opened. 0 and 1 are
   reserved. Repeated calls with the same file returns a new file descriptor
   per call. */
int
syscall_open (const char *file)
{
  if (!is_valid_filename (file))
    return -1;
  return fd_open (file);
}

int fd_filesize (int fd)
{
  lock_filesys ();
  struct file *handle = filesys_get_file (fd);
  int return_value = (handle == NULL) ? -1 : file_length (handle);
  unlock_filesys ();
  return return_value;
}

/* -- System Call #7 --
   Returns the size of the file associated with the given fd, or -1
   if the fd does not exist for the given process. */
static int
syscall_filesize (int fd)
{
  return fd_filesize (fd);
}

/* Given a file descriptor, read the given number of bytes from the file into
   the given buffer. Note that this function does NOT perform buffer checks. */
int
fd_read (int fd, void *buffer, unsigned size)
{
  lock_filesys ();
  struct file *handle = filesys_get_file (fd);
  if (handle == NULL)
    {
      unlock_filesys ();
      return -1;
    }
  off_t bytes_read = file_read (handle, buffer, size);
  unlock_filesys ();
  return bytes_read;
}

static int
console_read (char *buffer, unsigned size)
{
  unsigned i;
  for (i = 0; i < size; ++i)
    *(buffer++) = input_getc ();
  return size;
}

/* -- System Call #8 -- */
static int
syscall_read (int fd, char *buffer, unsigned size)
{
  int total_bytes = 0;
  while (size > 0)
    {
      unsigned bytes_on_page = PGSIZE - pg_ofs (buffer);
      unsigned bytes_to_read = (bytes_on_page) > size ? size : bytes_on_page;
      int bytes_read;
      
      if (!begin_page_operation (buffer, true))
        syscall_exit (-1);

      if (fd == STDIN_FILENO)
        bytes_read = console_read (buffer, size);
      else
        bytes_read = fd_read (fd, buffer, size);

      end_page_operation (buffer);
      total_bytes += bytes_read;
      size -= bytes_read;
      buffer += bytes_read;
      
      if (bytes_read != (int)bytes_to_read)
        return total_bytes;
    }
  return total_bytes;
}

int
fd_write (int fd, const void *buffer, unsigned size)
{
  lock_filesys ();
  struct file *handle = filesys_get_file (fd);
  if (handle == NULL)
    {
      unlock_filesys ();
      return -1;
    }
  off_t bytes_written = file_write (handle, buffer, size);
  unlock_filesys ();
  return bytes_written;
}

static int
console_write (const char *buffer, unsigned size)
{
  unsigned left_to_write = size;
  while (left_to_write > PUTBUF_BLOCK_SIZE)
    {
      putbuf (buffer, PUTBUF_BLOCK_SIZE);
      buffer = (const char*)buffer + PUTBUF_BLOCK_SIZE;
      left_to_write -= PUTBUF_BLOCK_SIZE;
    }
  putbuf (buffer, left_to_write);
  return size;
}

/* -- System Call #9 --
   Write size bytes from buffer to the given file file descriptor. Return
   the number of bytes written to the file. Note that fd == STDOUT_FILENO
   indicates that the buffer should be written to the console. */
static int
syscall_write (int fd, const void *buffer, unsigned size)
{
  int total_bytes = 0;
  while (size > 0)
    {
      unsigned bytes_on_page = PGSIZE - pg_ofs (buffer);
      unsigned bytes_to_write = (bytes_on_page) > size ? size : bytes_on_page;
      int bytes_written;
      
      if (!begin_page_operation (buffer, false))
        syscall_exit (-1);

      if (fd == STDOUT_FILENO)
        bytes_written = console_write (buffer, size);
      else
        bytes_written = fd_write (fd, buffer, size);

      end_page_operation (buffer);
      total_bytes += bytes_written;
      size -= bytes_written;
      buffer += bytes_written;
      
      if (bytes_written != (int)bytes_to_write)
        return total_bytes;
    }
  return total_bytes;
}

void
fd_seek (int fd, unsigned position)
{
  lock_filesys ();
  struct file *handle = filesys_get_file (fd);
  if (handle == NULL)
    {
      unlock_filesys ();
      return;
    }
  file_seek (handle, position);
  unlock_filesys ();
}

/* -- System Call #10 --
   Changes the next byte to be read or written in open file fd to
   position. */
static void
syscall_seek (int fd, unsigned position)
{
  fd_seek (fd, position);
}

/* -- System Call #11 --
   Returns the position of the next byte to be read or written in open
   file fd, expressed in bytes from the beginning of the file. */
static unsigned
syscall_tell (int fd)
{
  lock_filesys ();
  struct file *handle = filesys_get_file (fd);
  unsigned tellVal = file_tell (handle);
  unlock_filesys ();
  return tellVal;
}

/* -- System Call #12 --
   Closes the file associated with the given fd. */
static void
syscall_close (int fd)
{
  lock_filesys ();
  struct fd_elem *elem = filesys_get_fdelem (fd);
  if (elem != NULL)
    filesys_free_fdelem (elem);
  unlock_filesys ();
}

/* -- System Call #13 --
   Maps the file open as fd into consecutive virtual pages of the current
   process starting at addr. */
static mapid_t
syscall_mmap (int fd, void *vaddr)
{
  if (vaddr == 0 || vaddr >= PHYS_BASE || fd < 2 ||
      (pg_round_down (vaddr) != vaddr)) return -1;

  int id = process_add_mmap_from_fd (fd);
  if (id < 0) return -1;

  if (!process_create_mmap_pages (id, vaddr))
    {
      // TODO : Remove the mmap from the process mmap table
      return -1;
    }
  return id;
}

/* -- System Call #14 --
   Unmaps the mapping designated by mapping. */
static void
syscall_munmap (mapid_t mapid)
{
  process_remove_mmap (mapid);
}


static void
syscall_handler (struct intr_frame *f)
{
  thread_current ()->esp = f->esp;
  /* Attempt to translate the stack pointer to a physical address. */
  const void* esp = translate_vaddr(f->esp);
  if (esp == NULL)  goto abort;
  
  /* Read the system call number. */
  uint8_t syscall_number = *(uint8_t*)esp;

  /* Verify that the system call number is in bounds of what we
     are expecting. */
  if (syscall_number >= sizeof(syscall_arg_count)) goto abort;

  /* Lookup the expected number of arguments that the system call takes. */
  uint8_t args = syscall_arg_count[syscall_number];

  /* Try to read the proper number of arguments off of the caller's stack.
     At each point along the way, we validate the pointer to the argument. */
  uint32_t arg[3];
  int i;
  for (i = 0; i < args; ++i)
    {
      const uint32_t *arg_address = (const uint32_t*)f->esp + i + 1;
      const uint32_t *phys_address = validate_buffer((const char*)arg_address,
                                                     sizeof (uint32_t));
      if (phys_address == NULL) goto abort;
      arg[i] = *phys_address;
    }

  bool ret = false;
  int ret_val = -1;

  /* Jump to the proper system call based on the system call number. */
  switch (syscall_number)
    {
    case SYS_HALT:
      syscall_halt ();
      break;
    case SYS_EXIT:
      syscall_exit ((int)arg[0]);
      break;
    case SYS_EXEC:
      ret = true;
      ret_val = syscall_exec ((const char*)arg[0]);
      break;
    case SYS_WAIT:
      ret = true;
      ret_val = syscall_wait ((pid_t)arg[0]);
      break;
    case SYS_CREATE:
      ret = true;
      ret_val = syscall_create ((const char*)arg[0], (unsigned) arg[1]);
      break;
    case SYS_REMOVE:
      ret = true;
      ret_val = syscall_remove ((const char*)arg[0]);
      break;
    case SYS_OPEN:
      ret = true;
      ret_val = syscall_open ((const char*)arg[0]);
      break;
    case SYS_FILESIZE:
      ret = true;
      ret_val = syscall_filesize ((int)arg[0]);
      break;
    case SYS_READ:
      ret = true;
      ret_val = syscall_read ((int)arg[0], (void*)arg[1],
                               (unsigned)arg[2]);
      break;
    case SYS_WRITE:
      ret = true;
      ret_val = syscall_write ((int)arg[0], (const void*)arg[1],
                               (unsigned)arg[2]);
      break;
    case SYS_SEEK:
      ret = false;
      syscall_seek((int)arg[0], (unsigned)arg[1]);
      break;
    case SYS_TELL:
      ret = true;
      ret_val = syscall_tell ((int)arg[0]);
      break;
    case SYS_CLOSE:      
      syscall_close ((int)arg[0]);
      break;
    case SYS_MMAP:
      ret = true;
      ret_val = syscall_mmap ((int)arg[0], (void*)arg[1]);      
      break;
    case SYS_MUNMAP:
      ret = false;
      syscall_munmap ((mapid_t)arg[0]);
      break;
  }
 
  if (ret)
    f->eax = ret_val;
  return;

abort:
  syscall_exit (-1);
  return;
}
