#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

static uint32_t syscall_next_pid;

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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_next_pid = 0;
  process_init ();
}

/* Attempts to translate the given virtual address into a physical address,
   returning NULL if the virtual memory has not yet been mapped. */
static void*
translate_vaddr (const void* vaddr)
{
  if (!is_user_vaddr (vaddr))
    return NULL;
  return pagedir_get_page (thread_current ()->pagedir, vaddr);
}

/* Checks the supposed string in user memory at the given location, making
   sure that the string is safe to read. Additionally, checks to make sure
   that the string is <= max_length in size. If the string is unsafe or too
   big, returns -1. Otherwise, returns the length of the (safe) string. */
static int
translate_str (const char* vstr, int max_length)
{
  int i;
  for (i = 0; i <= max_length; ++i)
  {
    char *c = translate_vaddr(vstr++);
    if (c == NULL)
      return -1;
    if (*c == '\0')
      return i;
  }
  
  return -1;
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

/* -- System Call #2 --
   Executes the given command line, returning the child process' pid, or
   -1 if the child process fails to load or run for some reason. */
static pid_t
syscall_exec (const char *cmd_line)
{
  if (translate_str (cmd_line, PGSIZE) == -1)
    syscall_exit (-1);

  tid_t tid = process_execute (cmd_line);
  return tid == TID_ERROR ? -1 : tid;
}

/* -- System Call #3 -- */
static int
syscall_wait (pid_t pid)
{
  return process_wait (pid);
}

// Helper functions for locking and unlocking the file system
static void
lock_filesystem (void)
{
}

static void
unlock_filesystem (void)
{
}

/* -- System Call #4 --
   Creates a new file initially initial_size in bytes. Returns true if
   successful, false otherwise. Does not open the new file. */
static bool
syscall_create (const char *file, unsigned initial_size)
{
  if (file == NULL || translate_str(file, NAME_MAX) == -1)
    return false;
  lock_filesystem();
  bool success = filesys_create(file, initial_size);
  unlock_filesystem();
  return success;
}

/* -- System Call #5 --
   Deletes the file called file. Returns true if successful, false
   otherwise. A file can be removed whether it is opened or closed. If it
   is still opened (file descriptor exists referring to it) file can still
   be read and write from, but it no longer has a name and no one else can
   open it. */
static bool
syscall_remove (const char *file)
{
  if (file == NULL || translate_str(file, NAME_MAX) == -1)
    return false;
  lock_filesystem();
  bool success = filesys_remove(file);
  unlock_filesystem();
  return success;
}

/* -- System Call #6 --
   Opens a file called file. Returns a nonnegative file descriptor unique
   per process (but not across processes) or -1 if file could not be
   opened. 0 and 1 are reserved. Repeated calls with the same file returns
   a new file descriptor per call */
static int
syscall_open (const char *file)
{
  if (file == NULL || translate_str(file, NAME_MAX) == -1)
    return -1;
  lock_filesystem();
  struct file* fileOpen = filesys_open(file);
  if (fileOpen != NULL)
    {
      // TODO add fileOpen to list of files
      unlock_filesystem ();
      return thread_current ()->fileNumber++;
    }
  else
    {
      unlock_filesystem ();
      return -1;
    }
}


/* -- System Call #9 --
   Write size bytes from buffer to the given file file descriptor. Return
   the number of bytes written to the file. Note that fd == STDOUT_FILENO
   indicates that the buffer should be written to the console. */
static int
syscall_write (int fd, const void *buffer, unsigned size UNUSED)
{
  if (fd == STDOUT_FILENO)
  {
    /* TODO : Make this safe by checking the buffer bounds. Currently,
       this is NOT safe. The user program could cause us to overrun
       the bounds of valid virtual memory. */
    putbuf (translate_vaddr(buffer), size);
    return size;
  }
  else
  {
    // TODO : Implement writing to a file
    return -1;
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
  void* esp = translate_vaddr(f->esp);
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
      uint32_t *arg_address = translate_vaddr ((uint32_t*)f->esp + i + 1);
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
      ret_val = syscall_create((const char*)arg[0], (unsigned) arg[1]);
      break;
    case SYS_REMOVE:
      ret = true;
      ret_val = syscall_remove((const char*)arg[0]);
      break;
    case SYS_OPEN:
      ret = true;
      ret_val = syscall_open((const char*)arg[0]);
      break;
    case SYS_WRITE:
      ret = true;
      ret_val = syscall_write ((int)arg[0], (const void*)arg[1],
                               (unsigned)arg[2]);
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
