#include "devices/input.h"
#include "lib/kernel/hash.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

static unsigned filesys_fdhash_func (const struct hash_elem *e,
                                     void *aux);

static bool filesys_fdhash_less (const struct hash_elem *a,
                                 const struct hash_elem *b,
                                 void *aux UNUSED);

static struct lock filesys_lock;    /* Lock for file system access. */
static struct hash filesys_fdhash;  /* Hash table mapping fds to
                                       struct file*s. */

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
  1       /* Close */
};

struct fd_elem
{
  struct hash_elem h_elem;          /* Element hash table insertion. */
  struct list_elem l_elem;          /* Element for list insertion. */
  int fd;                           /* Associated fd number. */
  int owner_pid;                    /* pid of the owning process. */
  struct file *file;                /* File system file handle. */
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
  hash_init (&filesys_fdhash, filesys_fdhash_func, filesys_fdhash_less, NULL);
  process_init ();
}

/* Hash function for fd_elems. */
static unsigned
filesys_fdhash_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct fd_elem *elem = hash_entry(e, struct fd_elem, h_elem);
  return (unsigned)elem->fd;
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

/* Frees the resources associated with the given file descriptor
   element. This includes removing it from the global fd hash table,
   removing it from the owning thread's fd list, and freeing the
   associated memory. */
static void
filesys_free_fdelem (struct fd_elem *elem)
{
  file_close (elem->file);
  hash_delete (&filesys_fdhash, &elem->h_elem);
  list_remove (&elem->l_elem);
  free (elem);
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

/* Return the file struct associated with the given fd number, or
   NULL if the given fd does not exist. */
static struct file*
filesys_get_file (int fd)
{
  struct fd_elem *found = filesys_get_fdelem (fd);
  return found != NULL ? found->file
                       : NULL;
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
      filesys_free_fdelem (list_entry (e, struct fd_elem, l_elem));
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
   returns NULL. */
static const void*
validate_buffer (const void *buffer, int size)
{
  const void *begin = translate_vaddr(buffer);
  const void *end = translate_vaddr((const char*)buffer + size - 1);
  
  return (begin != NULL && end != NULL) ? begin : NULL;
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
  // TODO : Return this code to anyone that's waiting on me
  process_release (code);
  thread_exit ();
}

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

  lock_filesys ();
  bool success = filesys_remove (file);
  unlock_filesys ();
  return success;
}

/* -- System Call #6 --
   Opens a file called file. Returns a nonnegative file descriptor that is
   globally unique, or -1 if the file could not be opened. 0 and 1 are
   reserved. Repeated calls with the same file returns a new file descriptor
   per call. */
static int
syscall_open (const char *file)
{
  if (!is_valid_filename (file))
    return -1;

  lock_filesys ();
  struct file* handle = filesys_open (file);
  
  if (handle == NULL)
    {
      unlock_filesys ();
      return -1;
    }

  struct fd_elem *newhash = malloc (sizeof(struct fd_elem));
  newhash->fd = allocate_fd ();
  newhash->file = handle;
  newhash->owner_pid = thread_current ()->tid;

  //printf ("Opening 0x%x\n", handle);
  hash_insert (&filesys_fdhash, &newhash->h_elem);
  list_push_back (&thread_current ()->open_files, &newhash->l_elem);
  
  // TODO add file_handle to list of files
  unlock_filesys ();
  return newhash->fd;
}

/* -- System Call #7 -- */
static int
syscall_filesize (int fd)
{
  lock_filesys ();
  struct file *handle = filesys_get_file (fd);
  int return_value = (handle == NULL) ? -1 : file_length (handle);
  unlock_filesys ();
  return return_value;
}

/* -- System Call #8 -- */
static int
syscall_read (int fd, void *buffer, unsigned size)
{
  char *cbuffer = (char*)validate_buffer (buffer, size);
  if (cbuffer == NULL)
    syscall_exit (-1);

  if (fd == STDIN_FILENO)
    {
      unsigned i;
      for (i = 0; i < size; ++i)
        *(cbuffer++) = input_getc ();
      return size;
    }
  else
    {
      lock_filesys ();
      struct file *handle = filesys_get_file (fd);
      if (handle == NULL)
        {
          unlock_filesys ();
          return -1;
        }
      //printf ("Reading %d bytes from 0x%x\n", size, handle);
      off_t bytes_read = file_read (handle, buffer, size);
      unlock_filesys ();
      return bytes_read;
    }
}

/* -- System Call #9 --
   Write size bytes from buffer to the given file file descriptor. Return
   the number of bytes written to the file. Note that fd == STDOUT_FILENO
   indicates that the buffer should be written to the console. */
static int
syscall_write (int fd, const void *buffer, unsigned size)
{
  buffer = validate_buffer (buffer, size);
  if (buffer == NULL)
    syscall_exit (-1);

  if (fd == STDOUT_FILENO)
    {
      /* TODO : Make this safe by checking the buffer bounds. Currently,
         this is NOT safe. The user program could cause us to overrun
         the bounds of valid virtual memory. */
      putbuf (buffer, size);
      return size;
    }
  else
    {
      lock_filesys ();
      struct file *handle = filesys_get_file (fd);
      if (handle == NULL)
        {
          unlock_filesys ();
          return -1;
        }
      //printf ("Writing 0x%x\n", handle);
      off_t bytes_written = file_write (handle, buffer, size);
      unlock_filesys ();
      return bytes_written;
    }
}

/* -- System Call #10 --
   Changes the next byte to be read or written in open file fd to
   position. */
static void
syscall_seek (int fd, unsigned position)
{
  lock_filesys ();
  struct file *handle = filesys_get_file (fd);
  file_seek (handle, position);
  unlock_filesys ();
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

#if 0
#define D(x) x
#else
#define D(x)
#endif

static void
syscall_handler (struct intr_frame *f)
{
  D(printf ("\nSystem Call:\n"));
  D(printf ("\tMy Parent is: 0x%x\n", thread_current ()->parent));
  D(printf ("\tMy Parent is: %s\n", thread_current ()->parent->name));
  if (intr_get_level () == INTR_OFF)
    {D(printf ("\tInterrupts are OFF\n"));}
  else
    {D(printf ("\tInterrupts are ON\n"));}
  D(printf ("\tesp vaddr: 0x%x\n", f->esp));
  
  /* Attempt to translate the stack pointer to a physical address. */
  const void* esp = translate_vaddr(f->esp);
  if (esp == NULL)  goto kill;
  
  D(printf ("\tesp paddr: 0x%x\n", esp));

  /* Read the system call number. */
  uint32_t syscall_number = *(int*)esp;
  D(printf ("\tcall number: %d\n", syscall_number));

  /* Verify that the system call number is in bounds of what we
     are expecting. */
  if (syscall_number >= sizeof(syscall_arg_count)) goto kill;

  /* Lookup the expected number of arguments that the system call takes. */
  uint8_t args = syscall_arg_count[syscall_number];
  D(printf ("\targuments: %d\n", args));

  /* Try to read the proper number of arguments off of the caller's stack.
     At each point along the way, we validate the pointer to the argument. */
  uint32_t arg[3];
  int i;
  for (i = 0; i < args; ++i)
    {
      // TODO : Make sure this address is valid!
      const uint32_t *arg_address = translate_vaddr ((uint32_t*)f->esp + i + 1);
      if (arg_address == NULL) goto kill;
      arg[i] = *arg_address;
      D(printf ("\t\t[%d]: %d (0x%x)\n", i, arg[i], arg[i]));
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
      ret_val = syscall_tell((int)arg[0]);
      break;
    case SYS_CLOSE:      
      syscall_close ((int)arg[0]);
      break;
  }
 
  if (ret)
    f->eax = ret_val;
  return;

kill:
  D(printf ("Something went wrong, I'm killing this process.\n"));
  syscall_exit (-1);
  return;
}
