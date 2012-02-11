#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

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

/* Invoked when the system call detects a problem with address translation
   (i.e., the user gave us some bad arguments). Kills the process and
   releases all process resources. */
static void
syscall_kill (void)
{
  // TODO : Kill process AND RELEASE RESOURCES
  thread_exit ();
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
  printf("%s: exit(%d)\n", thread_current ()->name, code); 
  thread_exit ();
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
  D(printf ("\nSystem Call:\n\tesp vaddr: 0x%x\n", f->esp));
  
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
      uint32_t *arg_address = translate_vaddr((uint32_t*)f->esp + i + 1);
      if (arg_address == NULL) goto kill;
      arg[i] = *arg_address;
      D(printf ("\t\t[%d]: %d (0x%x)\n", i, arg[i], arg[i]));
    }

  int ret = -1;
  switch (syscall_number)
    {
      case 0:
        syscall_halt ();
        break;
        
      case 1:
        syscall_exit ((int)arg[0]);
        break;

      case 9:
        ret = syscall_write ((int)arg[0], (const void*)arg[1], (unsigned)arg[2]);
        break;
    }

  if (ret != -1)
    f->eax = ret;
  return;

kill:
  D(printf ("Something went wrong, I'm killing this process.\n"));
  syscall_kill ();
  return;
}
