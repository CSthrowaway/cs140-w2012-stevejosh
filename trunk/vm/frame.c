#include "vm/frame.h"
#include "lib/kernel/list.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

static struct list frames_allocated;

void
frame_init (void)
{
  // TODO : Call this from somewhere!
  list_init (&frames_allocated);
}

struct frame_elem*
frame_get (struct page_table_entry *vpage)
{
  void *page = palloc_get_page (PAL_USER);
  if (page == NULL)
    {
      /* OH SHIT, GOTTA EVICT EM. 
         TODO : Evict sumbodeh. */
      return NULL;
    }
  else
    {
      struct frame_elem* frame = malloc (sizeof(struct frame_elem));
      if (frame == NULL)
          PANIC ("frame_get: unable to allocate frame");
      list_init (&frame->users);
      frame->page = page;
      list_push_back (&frame->users, &vpage->l_elem);
      return frame;
    }
}
