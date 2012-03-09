#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/fixed-point.h"
#include "devices/timer.h"
#include "threads/fixed-point.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* List of processes currently in sleep. Added upon call to timer_sleep
   removed when added to ready_list */
static struct list sleep_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */
static real load_avg;           /* load average for BSD scheduling */

/* Scheduling. */
#define TIME_SLICE 1            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  list_init (&sleep_list);

  load_avg = 0;
  
  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
#ifdef FILESYS
  initial_thread->cwd = dir_open_root ();
#endif
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Gets the number of ready threads. For use in bsd scheduling */
static int
thread_get_ready_threads (void)
{
  ASSERT (thread_mlfqs);

  int ready_threads = list_size (&ready_list);
  /* If we aren't the idle thread, then we should count as one
     of the threads ready to be run. */
  if (running_thread () != idle_thread)
    ready_threads++;
  
  return ready_threads;
}

static void
thread_update_recent_cpu (struct thread *t, void *aux UNUSED)
{
  ASSERT (thread_mlfqs);

  real c = fixed_point_divide (2 * load_avg, 
			       2 * load_avg + fixed_point_create (1,1));
  c = fixed_point_multiply (t->recent_cpu, c);
  c += fixed_point_create(t->nice, 1);
  t->recent_cpu = c;
}

/* Updates the recent cpu and load average used in bsd scheduling */
static void
thread_update_bsd_stats (void)
{
  ASSERT (thread_mlfqs);

  /* Update load average. */
  int ready_threads = thread_get_ready_threads ();
  load_avg = fixed_point_multiply (fixed_point_create (59, 60), load_avg);
  load_avg += fixed_point_create (1, 60) * ready_threads;

  // update recent_cpu
  thread_foreach (thread_update_recent_cpu, NULL);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  if (thread_mlfqs)
    {
      t->recent_cpu += fixed_point_create (1, 1);

      /* Update recent_cpu and load_avg on ticks landing on a new second */
      if ((timer_ticks () % TIMER_FREQ) == 0)
    	  thread_update_bsd_stats();
  	}
	
  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);

  /* Add to run queue. */
  thread_unblock (t);
  /* Yield if the new thread is higher-priority than us */
	thread_yield_to_max ();

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Comparator for thread priorities. Will result in round-
   robin scheduling for threads of equal priorities, but will
   favor higher priorities in other cases. */
bool
thread_priority_cmp (const struct list_elem *a,
                     const struct list_elem *b,
                     void *aux UNUSED)
{
  return list_entry (a, struct thread, elem)->priority >
         list_entry (b, struct thread, elem)->priority;
}

/* Return the maximal priority of all threads, or -1 if
   no other threads exist. */
static int
thread_max_priority (void)
{
  /* We need to disable interrupts here so that the race (detailed
     below) doesn't occur. */
  enum intr_level old_level;
  old_level = intr_disable ();
  int return_value = -1;

  if (list_begin (&ready_list) != list_end (&ready_list))
    {
      /* Race condition exists here if interrupts are not disabled:
         if there is only one other thread ready and that thread
         interleaves here, then blocks, then the ready list will
         be empty when we run again, even though we think it's got
         something in it, and will end up reading bogus memory below */
      struct thread *t = list_entry (list_begin (&ready_list),
                                     struct thread, elem);
      return_value = t->priority;
    }
    
  intr_set_level (old_level);
  return return_value;
}

/* Check to see if we're one of the highest-priority threads.
   If not, yield. */
void
thread_yield_to_max (void)
{
  if (thread_max_priority () > thread_get_priority ())
    thread_yield ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_insert_ordered (&ready_list, &t->elem, thread_priority_cmp, NULL);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread)
    list_insert_ordered (&ready_list, &cur->elem, thread_priority_cmp, NULL);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Returns the thread t's maximal donated priority, or
   PRI_MIN if the thread has no priority donations in effect. */
static int
thread_get_donated_priority (struct thread *t)
{
  ASSERT (is_thread (t));
  
  if (list_begin (&t->priority_donations) != list_end (&t->priority_donations))
    {
      struct thread *top = list_entry (list_begin (&t->priority_donations),
                                       struct thread, donation_elem);
      return top->priority;
    }
  return -1;
}

/* Removes a thread from the ready list and then inserts it back in so the
   ready list maintains correct ordering */
static void
thread_reinsert_ready_list (struct thread *t)
{
  if (t->status == THREAD_READY)
    {
      /* Interrupts should already be off for
         non-running threads */
      ASSERT (intr_get_level () == INTR_OFF);
      
      list_remove(&t->elem);
      list_insert_ordered(&ready_list, &t->elem, thread_priority_cmp, NULL);
    }
}

/* Calculates and sets the current thread's priority, taking
   into consideration all priority donations that are in effect,
   as well as the thread's base priority. */
void
thread_calculate_priority (struct thread *t)
{
  ASSERT (is_thread (t));
  
  int donated_priority = thread_get_donated_priority (t);
  if (donated_priority > t->base_priority)
    t->priority = donated_priority;
  else
    t->priority = t->base_priority;

  thread_reinsert_ready_list(t);
}

/* Calculates and sets the current thread's priority, based on
   the BSD scheduler priority formula */
void
thread_calculate_priority_bsd (struct thread *t, void *aux UNUSED)
{
  ASSERT (is_thread (t));
  ASSERT (thread_mlfqs);

  /* Calculate the new priority of the thread */
  t->priority = PRI_MAX
                - fixed_point_round_nearest (t->recent_cpu / 4)
                - (t->nice * 2);
}

/* Sets the current thread's priority to NEW_PRIORITY.
   If we now have a lower priority than any other thread,
   we yield. */
void
thread_set_priority (int new_priority) 
{
  ASSERT (!thread_mlfqs); // Only relevant for priority scheduling

  thread_current ()->base_priority = new_priority;
  thread_calculate_priority (thread_current ());
  thread_yield_to_max ();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Priority comparison for threads in the priority_donation list. Keeps
   the list of priority donations ordered from greatest to least, making
   it a priority queue of priority donations. */
static bool
thread_donation_cmp (const struct list_elem *a,
                     const struct list_elem *b,
                     void *aux UNUSED)
{
  return list_entry (a, struct thread, donation_elem)->priority >
         list_entry (b, struct thread, donation_elem)->priority;
}

/* Recompute the effective priority of the given thread, then donate
   priority as necessary if the thread is waiting on a lock. Will be
   called recursively if the given thread is waiting on another. */
void
thread_donate_priority (struct thread *t)
{
  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (is_thread (t));

  /* Recalculate our priority, in case someone else bumped us. */
  thread_calculate_priority (t);

  if (t->waiting_on != NULL)
    {
      struct thread *waiter = t->waiting_on->holder;
      
      /* If this isn't the running thread and it's waiting on something,
         then it must have already donated to another thread, so we need
         to remove and re-insert that donation to preserve ordering. */
      if (running_thread() != t)
        thread_recall_donation (t);
    
      if (waiter != NULL)
        {
          /* Make the donation. */
          list_insert_ordered (&waiter->priority_donations, &t->donation_elem,
                               thread_donation_cmp, NULL);
      
          /* Recursively call this function on the thread we're waiting on
             so that it updates its own effective priority and updates its
             own donations appropriately. */
          thread_donate_priority (waiter);
        }
    }
}

/* Remove the given thread's priority donation.
   NOTE : Assumes the following :
     1. The given thread has already made a donation
     2. The donor does not need to recompute effective priority */
void
thread_recall_donation (struct thread *t)
{
  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (is_thread (t));
  
  list_remove (&t->donation_elem);
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) 
{
  ASSERT(thread_mlfqs);
  thread_current ()->nice = nice;  
  thread_calculate_priority_bsd (thread_current (), NULL);
  thread_reinsert_ready_list (thread_current ());
  thread_yield_to_max ();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  ASSERT(thread_mlfqs);
  return thread_current ()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  ASSERT(thread_mlfqs);
  return 100 * fixed_point_round_nearest (load_avg);
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  ASSERT(thread_mlfqs);
  return 100 * fixed_point_round_nearest (thread_current ()->recent_cpu);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED)
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;)
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->fileNumber = 2; // Reserve 0 and 1 for stdin and stdout
  t->base_priority = priority;
  t->magic = THREAD_MAGIC;
  t->parent = running_thread ();
  cond_init (&t->child_changed);
  lock_init (&t->child_changed_lock);
  list_init (&t->children);
  list_init (&t->open_files);
  list_init (&t->priority_donations);
#ifdef VM
  list_init (&t->mmap_table);
#endif
#ifdef FILESYS
  t->cwd = t->parent->cwd;  
#endif
  list_push_back (&all_list, &t->allelem);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}


/* Comparison function for comparing the sleep values of two thread
   structs. Returns true if a->wakeup_time < b->wakeup_time */
static bool 
thread_sleep_cmp (const struct list_elem *a, 
		  const struct list_elem *b, 
		  void *aux UNUSED)
{
  return list_entry (a, struct thread, sleep_elem)->wakeup_time < 
         list_entry (b, struct thread, sleep_elem)->wakeup_time;
}

/* Puts a thread to sleep until the given wake_time. The thread is
   inserted into the sleep_list and then blocked */
void
thread_sleep (int64_t wake_time)
{
  ASSERT(thread_current () != idle_thread);

  enum intr_level old_level;
  old_level = intr_disable ();
  
  /* Set our wakeup time appropriately */
  struct thread *t = thread_current ();
  t->wakeup_time = wake_time;

  /* Add thread to sleep_list, preserve soonest-time-first ordering */
  list_insert_ordered (&sleep_list, &t->sleep_elem, thread_sleep_cmp, NULL);

  /* Block the thread */
  thread_block ();
  intr_set_level (old_level);
}

/* Updates sleep threads to determine which if any are ready to be set
   to unblocked */
static void
schedule_update_sleep_threads (void)
{
  int64_t time = timer_ticks ();
  while (list_begin (&sleep_list) != list_end (&sleep_list))
    {
      struct thread* front_thread = list_entry (list_begin (&sleep_list),
                                                struct thread, sleep_elem);

      /* Since sleep_list is kept in ascending order of wakeup_time,
         we need only check that the front elem is not ready to wake.
         If that's the case, none of the elements are ready. */
      if (front_thread->wakeup_time > time)
      	break;

      thread_unblock (front_thread);
      list_pop_front (&sleep_list);      
    }
}

/* Recompute the priority for every thread, based on the BSD scheduler
   priority formula. */
static void
schedule_update_thread_priorities (void)
{
  ASSERT (thread_mlfqs);

  thread_foreach (thread_calculate_priority_bsd, NULL);
  list_sort (&ready_list, thread_priority_cmp, NULL);
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  if (thread_mlfqs)
    schedule_update_thread_priorities ();
  schedule_update_sleep_threads ();

  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
