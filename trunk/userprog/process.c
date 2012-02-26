#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static struct lock process_death_lock;  /* Must be acquired by a process that
                                           wishes to exit. */

/* Initializes all static data associated with processes.
   Gets called from syscall_init in syscall.c */
void
process_init (void)
{
  lock_init (&process_death_lock);
}

static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *process_information;
  tid_t tid;

  /* We're going to assume that file_name[file_name_length] and
     file_name[file_name_length + 1] exist and are on the page,
     so make sure that file_name is sized appropriately. Note that
     we also need room for an additional pointer, which will store
     the pointer to the child's status block. */
  if (strlen (file_name) >= PGSIZE - 2 - sizeof(void*))
    return TID_ERROR;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  process_information = palloc_get_page (PAL_ZERO);
  if (process_information == NULL)
    return TID_ERROR;
    
  /* Start the copy of file_name at a 4-byte offset, we'll save
     the first 4 bytes for a pointer to the status block. */
  char *fn_copy = &process_information[sizeof(void*)];
  strlcpy (fn_copy, file_name, PGSIZE);
  
  /* For now, break the string such that the filename is
     separate from any arguments. This will allow us to use the
     same memory for both the name and arguments, while still
     producing the correct thread name. */
  fn_copy[strcspn (fn_copy, " ")] = '\0';

  /* Create a child status block for the process we're about to spawn,
     initialize it to indicate that the process has not yet attempted to
     load, then add it to the list of child process status blocks. */
  struct child_status *child_status = malloc(sizeof(struct child_status));
  
  /* Check that malloc succeeded. */
  if (child_status == NULL)
    {
      palloc_free_page (process_information);
      return TID_ERROR;
    }

  child_status->status = PROCESS_STARTING;
  list_push_back (&thread_current ()->children, &child_status->elem);

  /* Write the pointer to the child status block to the process information
     page. */
  *(struct child_status**)process_information = child_status;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (fn_copy, PRI_DEFAULT,
                       start_process, process_information);
  
  /* If it failed to start, free the memory that we had allocated. */
  if (tid == TID_ERROR)
    {
      list_remove (&child_status->elem);
      free (child_status);
      palloc_free_page (process_information);
      return TID_ERROR;
    }

  /* Update the status block to reflect the child's pid (pid of
     process == tid of thread running the process) */
  child_status->pid = tid;

  /* Wait until the child's status block indicates that the child process
     has changed state. Do so using our child_changed condition variable. */
  lock_acquire (&thread_current ()->child_changed_lock);
  enum process_status cstatus = child_status->status;
  while (cstatus == PROCESS_STARTING)
    {
      cond_wait (&thread_current ()->child_changed,
                 &thread_current ()->child_changed_lock);
      cstatus = child_status->status;
    }
  lock_release (&thread_current ()->child_changed_lock);

  /* If the process failed to load, free the status block and return error. */
  if (cstatus == PROCESS_FAILED)
    {
      list_remove (&child_status->elem);
      free (child_status);
      return TID_ERROR;
    }

  return tid;
}

/* Parses the argument string for a given command-line (given
   arg_string), and sets up the stack such that argc and argv are
   ready to be accessed by the user program. Returns false if
   the arguments are too big to fit on the stack, true if the
   function succeeded. */
static bool
start_process_parse_args (char **esp_ptr, char *arg_string)
{
  /* NOTE: this function recomputes file_name_length and strlen(arg_string) 
     even though the calling function will have already done so,
     but the readability gain is worth the *tiny* performance loss. */

  int args = 0;
  int whitespace_size = 0;
  char *arg_string_ptr = arg_string;

  /* Do an initial pass over the argument string to determine exactly
     how many arguments there are as well as how many bytes of whitespace
     there are. This will save us from having to use any temporary memory
     while we are setting up the stack with argv's contents. */
  {
    char c;
    bool in_whitespace = true;
    while ((c = *arg_string_ptr) != '\0')
      {
        if (c != ' ' && in_whitespace)
          {
            in_whitespace = false;
            args++;
          }
        else if (c == ' ')
          {
            if (!in_whitespace)
              in_whitespace = true;
            whitespace_size++;
          }
        arg_string_ptr++;
      }
  }

  /* Compute the amount of memory that will be required to store *all* of
     the contents of argv, including null-terminators. */
  int argv_memory = strlen (arg_string) - whitespace_size + args;
  
  /* For performance reasons, round argv_memory up to the nearest multiple
     of a word so that argc and argv will be word-aligned. */
  argv_memory = ROUND_UP (argv_memory, sizeof(int));

  int total_memory = argv_memory + sizeof(char*)*(args + 1) + sizeof(char**)
                     + sizeof(int) + sizeof(void*);
  if (total_memory >= PGSIZE)
      return false;
  
  /* Subtract argv_memory from esp so that we can start setting up argv's
     data. */
  *esp_ptr -= argv_memory;
  
  /* argv_array points to the beggining of the argv array. It is an array
     of char*s. Note that the + 1 is required because argv must be padded
     with a null pointer at the end. */
  char **argv_array = (char**)*esp_ptr - (args + 1);
  
  char *string_data = *esp_ptr;
  char *token, *save_ptr;
  int argv_index = 0;
  
  /* Break the argument string up into space-delimitted tokens. For each
     token, copy the token into the string_data section, set the
     corresponding argv element to point to the beginning of the token,
     and the increment the string_data pointer appropriately so that we
     put the next token in the right place. */
  for (token = strtok_r (arg_string, " ", &save_ptr);
        token != NULL;
        token = strtok_r (NULL, " ", &save_ptr))
    {
       strlcpy (string_data, token, argv_memory);
       argv_array[argv_index] = string_data;

       /* Note the +1 to account for the null terminator. */
       string_data += strlen (token) + 1;

       argv_index++;
    }

  /* Pad argv with a null pointer, as required by the C standard. */
  argv_array[args] = NULL;

  /* Decrement the stack pointer to point to the top of the argv array. */
  *esp_ptr -= sizeof(char*) * (args + 1);
  
  /* Decrement the stack pointer to point to char **argv, and write
     the pointer such that it contains the address of the first element
     of argv (which is argv_array). */
  *esp_ptr -= sizeof(char**);
  
  /* This is weird, but it's correct - esp is 'pointing to' to an array
     of char*. Hence, esp is effectively a char*** that we may dereference
     to obtain char **argv on the stack. */
  *(char***)(*esp_ptr) = argv_array;

  /* Decrement the stack pointer by the size of an integer and write
     the number of arguments. */
  *esp_ptr -= sizeof(int);
  *(int*)(*esp_ptr) = args;
  
  /* Finally, decrement the stack pointer by the size of an address and
     write a null pointer; this is the return address. */
  *esp_ptr -= sizeof(void*);
  *(void**)(*esp_ptr) = NULL;
  
  return true;
}

/* Change the running process' status to the given status, and notify the
   parent that this process has changed status.
   
   NOTE : Assumes that proper synchronization between the parent and child
          is already taken care of. This is an important point, as this could
          cause a bad memory access if the parent dies while this function
          is runnig. The caller should have already acquired the process
          death lock, or the parent should be waiting on the child such that
          we don't have to worry about death. */
static void
process_change_status (enum process_status status)
{
  thread_current ()->my_status->status = status;

  struct thread *parent = thread_current ()->parent;
  if (parent != NULL)
    {
      lock_acquire(&parent->child_changed_lock);
      cond_signal(&parent->child_changed, &parent->child_changed_lock);
      lock_release(&parent->child_changed_lock);
    }
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *process_information_)
{
  struct child_status *status_block =
    *(struct child_status**)process_information_;
  char *file_name = (char*)process_information_ + sizeof(void*);
  struct intr_frame if_;
  bool success;

  /* Create the process' supplemental page table, and acquire a lock on
     it. */
  thread_current ()->page_table = page_table_create ();
  lock_acquire (&thread_current ()->page_table->lock);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  lock_release (&thread_current ()->page_table->lock);

  /* Set the my_status pointer to point to the parent's child status
     block, as given in the process_information page. */
  thread_current ()->my_status = status_block;

  /* Determine the length of the entire argument string
     as well as the length of the actual executable path.
     If there are arguments after the filename, restore
     them by turning the null terminator into a space. */
  int file_name_length = strlen (file_name);
  if (file_name[file_name_length + 1] != '\0')
    file_name[file_name_length] = ' ';
  int arg_string_length = strlen (file_name);
  file_name[file_name_length] = '\0';

  if (arg_string_length > file_name_length)
    file_name[file_name_length] = ' ';

  /* Parse the arguments and set up the stack such that argc and
     argv are correctly-placed and reflective of the contents
     of the arguments in file_name. */
  if (success)
    success = start_process_parse_args ((char**)&if_.esp, file_name);
  
  /* If load or argument parsing failed, quit. */
  if (!success)
  {
    page_table_free (thread_current ()->page_table);
    process_change_status (PROCESS_FAILED);
    palloc_free_page (process_information_);
    filesys_free_open_files (thread_current ());
    thread_exit ();
  }
  
  thread_current ()->executable = filesys_open (file_name);
  file_deny_write (thread_current ()->executable);
  
  palloc_free_page (process_information_);
  process_change_status (PROCESS_STARTED);
  
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Iterates through the list of this process' children and returns
   the child status block for the given pid, or NULL if the child
   does not exist. */
static struct child_status *
get_child_status_block (pid_t pid)
{
  struct list *l = &thread_current()->children;

  struct list_elem *e;
  for (e = list_begin (l); e != list_end (l);
       e = list_next (e))
    {
      struct child_status *s = list_entry (e, struct child_status, elem);
      if (s->pid == pid)
        return s;
    }
  
  return NULL;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid)
{
  lock_acquire (&thread_current ()->child_changed_lock);
  
  struct child_status *status_block = get_child_status_block (child_tid);

  /* If we were unable to get the status block, then the process is not
     a real process, not our child, or has already been waited on. */
  if (status_block == NULL)
    {
      lock_release (&thread_current ()->child_changed_lock);
      return -1;
    }
  
  /* Wait until the process exits the PROCESS_STARTED status (meaning
     that the process has finished.) */  
  while (status_block->status == PROCESS_STARTED)
      cond_wait (&thread_current ()->child_changed,
                 &thread_current ()->child_changed_lock);

  int exit_code = status_block->exit_code;

  /* Remove the child's status block and free the memory, since we
     aren't allowed to wait on it again. */
  list_remove (&status_block->elem);
  free (status_block);

  lock_release (&thread_current ()->child_changed_lock);
  return exit_code;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Must be called before a running process gets killed.
   Unlike process_exit, this function has access to the
   exit code of the process, and will make preparations
   for the process to die. */
void
process_release (int exit_code)
{
  /* TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
     Clean up resources:
        mmaps
        page table
        SHIT.
  */
   
  lock_acquire (&process_death_lock);
  printf("%s: exit(%d)\n", thread_current ()->name, exit_code); 
 
  /* Check to see if I've been orphaned. If so, I'm responsible
     for cleaning up my child status block, since my parent no
     longer owns it. */
  if (thread_current ()->my_status->status == PROCESS_ORPHANED)
    free (thread_current ()->my_status);
    
  /* Otherwise, update my status block to indicate my exit code,
     and inform my parent that my status has changed. */
  else if (thread_current ()->parent != NULL)
    {
      thread_current ()->my_status->exit_code = exit_code;
      process_change_status (PROCESS_DONE);
    }

  /* Orphan all of my children. */
  struct list_elem *e;
  for (e = list_begin (&thread_current ()->children);
       e != list_end (&thread_current ()->children);)
    {
      struct child_status *s = list_entry (e, struct child_status, elem);

      /* Advance the iterator *before* we potentially free the memory. */
      e = list_next (e);

      /* If the process is no longer alive, we're responsible for
         freeing this memory. If they ARE alive, we need to orphan
         them so that they know that they're responsible for freeing
         their own status block. */
      if (s->status == PROCESS_DONE)
        free (s);
      else
        s->status = PROCESS_ORPHANED;
    }

  /* Free all of the open files that were associated with this process. */  
  filesys_free_open_files (thread_current ());

  /* Close the executable file and allow writing to it. */
  file_allow_write (thread_current ()->executable);
  file_close (thread_current ()->executable);
  
  lock_release (&process_death_lock);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}


/* Opens a new file from file_name and stores the file descriptor into the
   current thread's mmapid. */
int
process_add_mmap_from_name (const char *file_name)
{
  int fd = syscall_open (file_name);
  
  /* Return error if we failed to open. */
  if (fd <= 1)
    return -1;
  
  struct thread* t = thread_current ();
  int mapid = t->next_mapid++;
  struct mmap_table_entry* entry = malloc (sizeof(struct mmap_table_entry));
  if (entry == NULL)
    PANIC ("process_add_mmap_from_name: failed to allocate table entry");

  entry->id = mapid;
  entry->fd = fd;
  list_push_back (&t->mmap_table, &entry->elem);
  return mapid;
}

int 
process_add_mmap_from_fd (int fd)
{
  return process_add_mmap_from_name (filesys_get_filename_from_fd (fd));
}

/* Search through the process' active mmap table, and return the file
   descriptor associated with the given mmapid. Returns -1 if no such
   mmapid exists in the current process' mmap table. */
int
process_get_mmap_fd (mmapid_t mapid)
{
  // TODO Synchron!
  struct list_elem *e;
  
  struct list *mmap_table = &thread_current ()->mmap_table;
  for (e = list_begin (mmap_table); e != list_end (mmap_table);
       e = list_next (e))
    {
      struct mmap_table_entry *s =
        list_entry (e, struct mmap_table_entry, elem);
      if (s->id == mapid)
        return s->fd;
    }
    
  return -1;
}


/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }
    
  mmapid_t mmapid = process_add_mmap_from_name (file_name);

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;

              uint32_t i;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  //zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                  //              - read_bytes);

                  for (i = 0; i < read_bytes; i += PGSIZE)
                    {
                      struct frame *frame = frame_alloc ();
                      frame_set_mmap (frame, mmapid, file_page + i);
                      frame_set_attribute (frame, FRAME_READONLY, !writable);
                      page_table_add_entry (thread_current ()->page_table,
                                            (void *)(mem_page + i), frame);
                    }
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  //read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                  
                  for (i = 0; i < zero_bytes; i += PGSIZE)
                    {
                      struct frame *frame = frame_alloc ();
                      frame_set_zero (frame);
                      frame_set_attribute (frame, FRAME_READONLY, !writable);
                      page_table_add_entry (thread_current ()->page_table,
                                            (void *)(mem_page + i), frame);
                    }
                }
              
              //if (!load_segment (file, file_page, (void *) mem_page,
              //                   read_bytes, zero_bytes, writable))
              //  goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if (!success)
    // TODO TODO TODO TODO TODO TODO TODO TODO CLEAN UP THE MMAP
  
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
