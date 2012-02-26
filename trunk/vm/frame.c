#include "lib/kernel/list.h"
#include "lib/string.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/swap.h"

static struct list frames_allocated;

/* NOTE : Gets called by syscall_init in syscall.c. */
void
frame_init (void)
{
  list_init (&frames_allocated);
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
  if (frame->paddr != NULL)
    {
      palloc_free_page (frame->paddr);
      list_remove (&frame->elem);
    }
  free (frame);
}

/* Evict the given frame, returning the (now free) physical page that the
   frame was occyping. Will write the frame to swap or file if necessary. */
UNUSED static void*
frame_page_out (struct frame *frame UNUSED)
{
  void* paddr = frame->paddr;
  // TODO: EVICT THAT SON OF A BITCH
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
      filesys_seek (fd, frame->aux2);
      if (filesys_read (fd, frame->paddr, PGSIZE) != PGSIZE)
        PANIC ("frame_load_data: mmap failed to load file");
    }
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
      // TODO : Evict somebody and set page to be their old page.
      PANIC ("frame_page_in: eviction not yet implemented");
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
frame_set_mmap (struct frame *frame, mmapid_t id, uint32_t offset)
{
  frame->aux1 = id;
  frame->aux2 = offset;
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
