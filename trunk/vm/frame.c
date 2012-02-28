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
static struct lock frame_lock;

/* NOTE : Gets called by syscall_init in syscall.c. */
void
frame_init (void)
{
  list_init (&frames_allocated);
  lock_init (&frame_lock);
}

#include "lib/stdio.h"

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
  if (frame->paddr != NULL)
    {
      palloc_free_page (frame->paddr);
      list_remove (&frame->elem);
    }
  free (frame);
}

/* Load the given frame's data into physical memory. The method of doing so
   depends on whether the frame is zeroed, swapped, or mmapd. */
static void
frame_load_data (struct frame *frame)
{
  if (frame->status & FRAME_ZERO)
    memset (frame->paddr, 0, PGSIZE);
  else if (frame->status & FRAME_SWAP)
    {
      swap_read (frame->aux1, frame->paddr);
      swap_free (frame->aux1);
    }
  else if (frame->status & FRAME_MMAP)
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

static void
frame_save_data (struct frame *frame)
{
  /* If the frame started out as zero-filled page and was modified, we
     change it to be a swap page (since it is no longer all zeroes. */
  if (frame->status & FRAME_ZERO)
    {
      frame->status &= ~FRAME_ZERO;
      frame->status &= FRAME_SWAP;
    }

  if (frame->status & FRAME_SWAP)
  	{
      swapid_t id = swap_alloc ();
      swap_write (id, frame->paddr);
      frame->aux1 = id;
  	}
  else if (frame->status & FRAME_MMAP)
    {
      int fd = process_get_mmap_fd (frame->aux1);
      fd_seek (fd, frame->aux2);
      fd_write (fd, frame->paddr, PGSIZE);
    }
}

/* Evict the given frame, returning the (now free) physical page that the
   frame was occyping. Will write the frame to swap or file if necessary. */
static void*
frame_page_out (struct frame *frame)
{
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
      is_dirty |= pagedir_is_dirty (p->thread->pagedir, p->vaddr);
      page_table_entry_deactivate (p);
    }

  if (is_dirty)
    frame_save_data (frame);

  void* paddr = frame->paddr;
  frame->paddr = NULL;
  return paddr;
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

// TODO TODO TODO TODO IMPLEMENT CLOCK ALGORITHM
/* Chooses a frame to evict from the frames_allocated list, removing the
   frame from the list in the process. Synchronized with the frame lock, so
   that other processes don't try to evict it in the mean time.
   Evicts the first non accessed page. */
static struct frame*
frame_choose_eviction (void)
{
  lock_acquire (&frame_lock);
  struct frame *chosen = NULL;
  struct list_elem *f;

  for (f = list_begin (&frames_allocated);
       f != list_end (&frames_allocated);
       f = list_next (f))
    {
      struct frame *frame = list_entry (f, struct frame, elem);
      if (!frame_was_accessed (frame) && !(frame->status & FRAME_PINNED))
        {
          chosen = frame;
          break;
        }
    }

  /* If we weren't able to find a frame to evict, just pick the
     first in the allocated list. */
  if (chosen == NULL)    
    chosen = list_entry (list_begin (&frames_allocated), struct frame, elem);

  /* Remove the frame from the allocated frames list and release the frame
     lock. Once we take it off of the list, we're safe from someone else
     trying to grab it. */
  list_remove (&chosen->elem);
  lock_release (&frame_lock);
  return chosen;
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
  if (page == NULL)
    {
      struct frame* frame_to_evict = frame_choose_eviction();
      void* paddr = frame_page_out (frame_to_evict);
	    page = paddr;
    }

  frame->paddr = page;
  
  lock_acquire (&frame_lock);
  list_push_back (&frames_allocated, &frame->elem);
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
