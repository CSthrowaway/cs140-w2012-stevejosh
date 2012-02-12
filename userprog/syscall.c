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

struct fdhash_elem
{
  struct hash_elem elem;
  int fd;
  struct file *file;
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
  hash_init (&filesys_fdhash, filesys_fdhash_func, filesys_fdhash_less, NULL);
  process_init ();
}

/* Hash function for fdhash_elems. */
static unsigned
filesys_fdhash_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct fdhash_elem *elem = hash_entry(e, struct fdhash_elem, elem);
  return (unsigned)elem->fd;
}

/* Comparator for fdhash_elems. */
static bool
filesys_fdhash_less (const struct hash_elem *a,
                     const struct hash_elem *b,
                     void *aux UNUSED)
{
  struct fdhash_elem *a_e = hash_entry(a, struct fdhash_elem, elem);
  struct fdhash_elem *b_e = hash_entry(b, struct fdhash_elem, elem);
  return (a_e->fd < b_e->fd);
}

static struct hash_elem*
filesys_get_elem (int fd)
{
  struct fdhash_elem search;
  search.fd = fd;

  struct hash_elem *found;
  found = hash_find (&filesys_fdhash, &search.elem);

  if (found == NULL)
    return NULL;
    
  return found;
}

static struct file*
filesys_get_file (int fd)
{
  struct hash_elem *found = filesys_get_elem (fd);
  return found != NULL ? hash_entry (found, struct fdhash_elem, elem)->file
                       : NULL;
}

/* Return an integer >= 2 that is unique for the life of the kernel.
   NOTE : Assumes that the filesystem lock has already bee acquired! */
static int
allocate_fd (void)
{
  static int fd_current = 2;
  return fd_current++;
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
  if (file == NULL || (name_size = validate_str (file, NAME_MAX)) == -1)
    syscall_exit (-1);

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

  struct fdhash_elem *newhash = malloc (sizeof(struct fdhash_elem));
  newhash->fd = allocate_fd ();
  newhash->file = handle;

 // printf ("Opening 0x%x\n", handle);
  hash_insert (&filesys_fdhash, &newhash->elem);
  
  // TODO add file_handle to list of files
  unlock_filesys ();
  return newhash->fd;
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
      struct file *handle = filesys_get_file (fd);
      if (handle == NULL)
        return -1;
      //printf ("Reading 0x%x\n", handle);
      return file_read (handle, buffer, size);
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
      struct file *handle = filesys_get_file (fd);
      if (handle == NULL)
        return -1;
      //printf ("Writing 0x%x\n", handle);
      return file_write (handle, buffer, size);
    }
}

/* -- System Call #12 --
   Closes the file associated with the given fd. */
static void
syscall_close (int fd)
{
  struct file *handle = filesys_get_file (fd);
  if (handle != NULL)
    {
      file_close (handle);
      struct hash_elem *elem = filesys_get_elem (fd);
      hash_delete (&filesys_fdhash, elem);
      free (elem);
    }
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
