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

/* NOTE : Gets called by syscall_init in syscall.c. */
void
frame_init (void)
{
  list_init (&frames_allocated);
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

/* Evict the given frame, returning the (now free) physical page that the
   frame was occyping. Will write the frame to swap or file if necessary. */
static void*
frame_page_out (struct frame *frame)
{
  ASSERT(IS_FRAME_PINNED(frame->status) == false);
  void* paddr = frame->paddr;
  
  // Determine if there is dirty data to write out
  bool isDirty = false;
  struct list_elem *e;
  for (e = list_begin (&frame->users); e != list_end (&frame->users); e = list_next (e))
    {
      struct page_table_entry *p = list_entry (e, struct page_table_entry, l_elem);
      uint32_t* pagedir = p->thread->pagedir;
      
      isDirty |= pagedir_is_dirty (pagedir, p->vaddr);
    }
  // Write out dirty data
  if (isDirty)
    {
      if (IS_FRAME_SWAP(frame->status))
	{
	  swapid_t id = swap_alloc();
	  swap_write(id, frame->paddr);
	  frame->aux1 = id;
	}
      else if (IS_FRAME_MMAP(frame->status))
	{
	  int fd = process_get_mmap_fd (frame->aux1);
	  fd_seek (fd, frame->aux2);
	  fd_write (fd, frame->paddr, PGSIZE);
	}
    }
  // remove from allocated list
  list_remove (&frame->elem);
  // mark physical address of evicted page as empty
  frame->paddr = NULL;
  return paddr;
}

/* Load the given frame's data into physical memory. The method of doing so
   depends on whether the frame is zeroed, swapped, or mmapd. */
static void
frame_load_data (struct frame *frame)
{
  if (frame->status & FRAME_ZERO)
    memset (frame->paddr, 0, PGSIZE);
  else if (frame->status & FRAME_SWAP)
    swap_read (frame->aux1, frame->paddr);
  else if (frame->status & FRAME_MMAP)
    {
      int fd = process_get_mmap_fd (frame->aux1);
      ASSERT (fd >= 0);
      int file_size = fd_filesize (fd);

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

/* Chooses a frame to evict from the frames_allocated list. Evicts the first non accessed page. */
static struct frame*
frame_choose_eviction ()
{
  struct list_elem *f;
  struct list_elem *p;
  // look through frames
  for (f = list_begin (&frames_allocated); f != list_end (&frames_allocated); f = list_next (f))
    {
      struct frame *cur = list_entry (f, struct frame, elem);
      bool isAccessed = false;
      // determines if any pages referencing current frame have recently
      // accessed the frame. Clears accessed reference bits as it goes
      for (p = list_begin (&cur->users); p != list_end (&cur->users); p = list_next (p))
	{
	  struct page_table_entry *page = list_entry (p, struct page_table_entry, l_elem);
	  uint32_t* pagedir = page->thread->pagedir;
	  if (pagedir_is_accessed (pagedir, page->vaddr))
	    {
	      isAccessed = true;
	      pagedir_set_accessed (pagedir, page->vaddr, false);
	    }
	}
      // If this frame was not accessed recently, then evict it
      if (!isAccessed)
	{
	  return cur;
	}
    }
  return NULL;
}

/* Force the given frame into physical memory, acquiring a physical frame
   for it as well as loading its data from the appropriate location. */
void
frame_page_in (struct frame *frame)
{
  ASSERT (frame->paddr == NULL);
  
  void *page = palloc_get_page (PAL_USER);
  if (page == NULL)
    {
      struct frame* frameToEvict = frame_choose_eviction();
      void* paddr = frame_page_out (frameToEvict);
      if (paddr == NULL)
	PANIC ("Could not choose a frame to evict");
      page = paddr;
    }
  frame->paddr = page;
  list_push_back (&frames_allocated, &frame->elem);

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
