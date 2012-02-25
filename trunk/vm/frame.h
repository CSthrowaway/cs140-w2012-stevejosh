#include "lib/kernel/list.h"
#include "vm/page.h"

typedef void* frame;

struct frame_elem
  {
    void *page;                     /* Physical address of this frame. */
    struct list users;              /* List of all virtual pages using this
                                       physical frame (will usually be a
                                       single page). */
  };

void frame_init (void);
struct frame_elem *frame_get (struct page_table_entry *vpage);
