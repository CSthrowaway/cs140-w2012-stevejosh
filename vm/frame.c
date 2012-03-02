#include "lib/kernel/list.h"
#include "lib/string.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/swap.h"

static struct list frames_allocated;
static struct list_elem *clock_hand = NULL;
static struct lock frame_lock;

/* NOTE : Gets called by syscall_init in syscall.c. */
void
frame_init (void)
{
  list_init (&frames_allocated);
  lock_init (&frame_lock);
}

struct frame*
frame_alloc (void)
{
  struct frame* frame = malloc (sizeof(struct frame));
  if (frame == NULL)
    PANIC ("frame_alloc: unable to allocate frame");

  memset (frame, 0, sizeof (struct frame));
  list_init (&frame->users);
  return frame;
}

void
frame_free (struct frame *frame)
{
  frame_page_out (frame);
  if (frame->paddr != NULL)
    {
      lock_acquire (&frame_lock);
      palloc_free_page (frame->paddr);
      list_remove (&frame->elem);
      lock_release (&frame_lock);
    }
  free (frame);
}

/* Load the given frame's data into physical memory. The method of doing so
   depends on whether the frame is zeroed, swapped, or mmapd. */
static void
frame_load_data (struct frame *frame)
{
  if (frame_get_attribute (frame, FRAME_ZERO))
    memset (frame->paddr, 0, PGSIZE);
  else if (frame_get_attribute (frame, FRAME_SWAP))
    {
      swap_read (frame->aux1, frame->paddr);
      swap_free (frame->aux1);
    }
  else if (frame_get_attribute (frame, FRAME_MMAP))
    {
      int fd = process_get_mmap_fd (frame->aux1);
      ASSERT (fd >= 0);

      /* Determine the proper number of bytes to read from the file.
         The remainder of the page should be zeroed. */ 
      int read_bytes = frame->aux3;
      int zero_bytes = PGSIZE - read_bytes;

      fd_seek (fd, frame->aux2);
      if (fd_read (fd, frame->paddr, read_bytes) != read_bytes)
        PANIC ("frame_load_data: mmap failed to load file");
      
      if (zero_bytes > 0)
        memset ((char*)frame->paddr + read_bytes, 0, zero_bytes);
    }
}

static struct list_elem *
clock_advance_hand (void)
{
  struct list_elem *old = clock_hand;
  
  if (list_size (&frames_allocated) == 0)
    return clock_hand = NULL;

  if (old == list_end (&frames_allocated))
    return clock_hand = list_begin (&frames_allocated);
  else
    {
      clock_hand = list_next (old);
      return old;
    }
}

static void
frame_save_data (struct frame *frame)
{
  /* If the frame started out as zero-filled page and was modified, we
     change it to be a swap page (since it is no longer all zeroes. */
  if (frame_get_attribute (frame, FRAME_ZERO))
    {
      frame_set_attribute (frame, FRAME_ZERO, false);
      frame_set_attribute (frame, FRAME_SWAP, true);
    }

  /* If the frame contains part of the code segment but was dirtied, we
     need to convert it to a swap page, because it can't be written back
     to the executable. */
  if (frame_get_attribute (frame, FRAME_CODE))
    {
      frame_set_attribute (frame, FRAME_MMAP, false);
      frame_set_attribute (frame, FRAME_SWAP, true);
    }

  if (frame_get_attribute (frame, FRAME_SWAP))
  	{
      swapid_t id = swap_alloc ();
      swap_write (id, frame->paddr);
      frame->aux1 = id;
  	}
  else if (frame_get_attribute (frame, FRAME_MMAP))
    {
      int fd = process_get_mmap_fd (frame->aux1);
      fd_seek (fd, frame->aux2);
      fd_write (fd, frame->paddr, PGSIZE);
    }
}

/* Evict the given frame from physical memory. Will write the frame to swap or
   file if necessary. The frame's physical memory gets freed via
   palloc_free_page, and goes back into the user page pool. */
void
frame_page_out (struct frame *frame)
{
  if (frame->paddr == NULL) return;
  ASSERT (!(frame->status & FRAME_PINNED));
  
  bool is_dirty = false;

  /* Iterate through all supplemental page table entries that are using this
     frame, checking to see whether or not they have caused the frame to be
     dirtied. */
  struct list_elem *e;
  for (e = list_begin (&frame->users);
       e != list_end (&frame->users);
       e = list_next (e))
    {
      struct page_table_entry *p = list_entry (e, struct page_table_entry,
                                               l_elem);
      if (pagedir_is_dirty (p->thread->pagedir, p->vaddr))
        is_dirty = true;
      page_table_entry_deactivate (p);
    }

  /* Release the lock while we're saving the frame data, as we'd like to let
     other processes proceed if they don't need to perform I/O. */
  lock_release (&frame_lock);
  // TODO set the "do not touch me" flag
  if (is_dirty || frame_get_attribute (frame, FRAME_SWAP))
    frame_save_data (frame);
  lock_acquire (&frame_lock);

  /* Remove the frame from the allocated frames list. */
  if (clock_hand == &frame->elem)
    clock_hand = list_next (&frame->elem);
  list_remove (&frame->elem);
  clock_advance_hand ();
  palloc_free_page (frame->paddr);
  frame->paddr = NULL;
}

/* Checks all virtual pages that are using this virtual frame to see if they
   have accessed the page since we last checked. Returns true if any of them
   have accessed this frame. Also resets all accessed flags for this frame. */
static bool
frame_was_accessed (struct frame *frame)
{
  bool accessed = false;
  struct list_elem *p;
  for (p = list_begin (&frame->users);
       p != list_end (&frame->users);
       p = list_next (p))
    {
      struct page_table_entry *pte = list_entry (p, struct page_table_entry,
                                                 l_elem);
      if (pagedir_is_accessed (pte->thread->pagedir, pte->vaddr))
        {
          accessed = true;
          pagedir_set_accessed (pte->thread->pagedir, pte->vaddr, false);
        }
    }
  return accessed;
}

/* Uses the clock algorithm to choose the "best" frame for eviction, given
   the candidates on the list of allocated frames. */
static struct frame*
frame_choose_eviction (void)
{
  while (true)
    {
      struct list_elem *candidate = clock_advance_hand ();
      if (candidate == NULL) return NULL;

      struct frame *frame = list_entry (candidate, struct frame, elem);
      if (!frame_was_accessed (frame) &&
          !frame_get_attribute (frame, FRAME_PINNED))
        return frame;
    }
}

/* Force the given frame into physical memory, acquiring a physical frame
   for it as well as loading its data from the appropriate location. */
void
frame_page_in (struct frame *frame)
{
  ASSERT (frame->paddr == NULL);
  
  void *page = palloc_get_page (PAL_USER);

  /* If we weren't able to allocated a new page, we'll have to evict an
     existing frame and steal its physical memory. */
  while (page == NULL)
    {
      // TODO : Fix synchro.
      lock_acquire (&frame_lock);
      struct frame* frame_to_evict = frame_choose_eviction ();
      frame_page_out (frame_to_evict);
      lock_release (&frame_lock);
      page = palloc_get_page (PAL_USER);
    }
  
  frame->paddr = page;
  
  lock_acquire (&frame_lock);
  list_push_back (&frames_allocated, &frame->elem);
  if (clock_hand == NULL)
    clock_hand = &frame->elem;
  lock_release (&frame_lock);

  frame_load_data (frame);
}

void
frame_set_attribute (struct frame *frame, uint32_t attribute, bool on)
{
  if (on)
    frame->status |= attribute;
  else
    frame->status &= ~attribute;
}

bool
frame_get_attribute (struct frame *frame, uint32_t attribute)
{
  return (frame->status & attribute) != 0;
}

/* Mark the given frame as mmapd. */
void
frame_set_mmap (struct frame *frame, mmapid_t id, uint32_t offset,
                uint32_t bytes_to_read)
{
  frame->aux1 = id;
  frame->aux2 = offset;
  frame->aux3 = bytes_to_read;
  frame->status |= FRAME_MMAP;
}

/* Mark the given frame as zero-filled. */
void
frame_set_zero (struct frame *frame)
{
  frame->status |= FRAME_ZERO;
}

/* Mark the given frame as swapped/swappable. */
void
frame_set_swap (struct frame *frame)
{
  frame->aux1 = -1;
  frame->status |= FRAME_SWAP;
}
