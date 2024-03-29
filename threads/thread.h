#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include <threads/synch.h>
#include <vm/page.h>
#include <filesys/directory.h>

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* States in a process' life cycle. 
   (Owned by userprog/process.c) */
enum process_status
  {
    PROCESS_STARTING,   /* Process has not yet started. */
    PROCESS_STARTED,    /* Process has successfully loaded. */
    PROCESS_FAILED,     /* Process failed to load. */
    PROCESS_DONE,       /* Process has terminated. */
    PROCESS_ORPHANED    /* The process' parent has died, so the process
                           must no longer try to report status changes
                           to the parent. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;

/* Process identifier type.
   Note that the pid of a user process is the same as
   the tid of the thread running the process. */
typedef int pid_t;

typedef int mapid_t;
/* Mmap identification type. */

#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Owned by userprog/process.c. */
struct child_status
  {
    struct list_elem elem;              /* List element for adding this struct
                                           to a process' list of children. */
    pid_t pid;                          /* pid of the child process. */
    enum process_status status;         /* process status of the child. */
    int exit_code;                      /* Exit code of process, only valid
                                           if the process has already
                                           run and terminated. */
  };

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int recent_cpu;                     /* Estimation of clock ticks
                                           recently used by this thread */
    int priority;                       /* Priority, including donations. */
    int base_priority;                  /* Base priority, before including
                                           priority donations. */
    int nice;                           /* Nice value for BSD scheduler */
    int64_t wakeup_time;                /* Time to wake up thread if asleep. */

    int fileNumber;                     /* Next available fileID. */
    struct list priority_donations;     /* Sorted list (high-to-low) of all
                                           priorities donated to this thread. */
    struct lock *waiting_on;            /* Lock that the thread is waiting
                                           to acquire. */
    /* List elements */
    struct list_elem elem;              /* List element. */
    struct list_elem allelem;           /* List element for all threads list. */
    struct list_elem sleep_elem;        /* List element for sleep threads. */
    struct list_elem donation_elem;     /* List element for donating a
                                           priority to other threads. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    struct file *executable;            /* Loaded executable for this user
                                           process. */
    struct thread *parent;              /* Parent thread. */
    struct child_status *my_status;     /* Pointer to this thread's child_status
                                           block in the parent thread. */                                        
    struct list children;               /* Child processes of this thread. */
    struct lock child_changed_lock;     /* Lock associated with the condition
                                           variable below. */
    struct condition child_changed;     /* Condition variable for signalling
                                           that one of this thread's children
                                           has changed status. */
    struct list open_files;             /* Files currently opened by this
                                           thread's process. */
#endif

#ifdef VM
    struct list mmap_table;             /* List of all process mmap data. */
    int next_mapid;                     /* Next mapid to be used in mmap. */
    void *esp;                          /* Last-known ESP upon context switch
                                           into kernel mode. */
    struct page_table *page_table;      /* Supplemental page table for virtual
                                           memory management. */
#endif

#ifdef FILESYS
    block_sector_t cwd;                 /* Sector of working dir. */
    struct file *cwd_file;              /* Opened working dir file. Used to
                                           prevent deletion of cwd. */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);
void thread_yield_to_max (void);

void thread_sleep(int64_t wake_time);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

void thread_calculate_priority (struct thread *t);
void thread_calculate_priority_bsd (struct thread *t, void* aux UNUSED);
void thread_donate_priority (struct thread *t);
bool thread_priority_cmp (const struct list_elem *a, const struct list_elem *b,
												  void *aux UNUSED);
int thread_get_priority (void);
void thread_set_priority (int);
void thread_recall_donation (struct thread *t);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */
