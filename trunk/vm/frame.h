#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/list.h"
#include "vm/page.h"

/* Below are the various status bits that may reside in a page_status
   bitfield. Some are mutually exclusive, such as FRAME_ZERO, FRAME_SWAP,
   and FRAME_MMAP, while some may be mixed (for example, FRAME_SWAP,
   FRAME_PINNED, FRAME_LOCKED may all be on at the same time). */
#define FRAME_ZERO      0x1        /* Set when the frame is zero-filled. */
#define FRAME_SWAP      0x2        /* Set when the frame is to be loaded and
                                      saved to/from a swap slot. */
#define FRAME_MMAP      0x4        /* Set when the frame is to be loaded and
                                      saved to/from a file. */
#define FRAME_PINNED    0x8        /* Set to protect frame from eviction. */
#define FRAME_READONLY  0x10       /* Set when the frame is not writeable. */
#define FRAME_CODE      0x20       /* Set when the frame came from a code
                                      segment (hence cannot be written back). */
#define FRAME_LOCKED    0x40       /* Set when the frame is not to be touched
                                      by anyone other than the locker. */
                                      
typedef int mmapid_t;

struct frame
  {
    void *paddr;                    /* Physical address of this frame. */
    uint32_t status;                /* Status bits (see #defines above). */
    uint32_t aux1;                  /* Swap slot OR mmapid. */
    uint32_t aux2;                  /* mmap file offset. */
    uint32_t aux3;                  /* mmap read bytes. */
    struct list_elem elem;          /* List element for allocated list. */
    struct list users;              /* List of all virtual pages using this
                                       physical frame (will usually be a
                                       single page). */
  };

void frame_init (void);
struct frame *frame_alloc (void);
void frame_free (struct frame *frame);
void frame_page_in (struct frame *frame);
void frame_page_out (struct frame *frame, bool dying);

bool frame_get_attribute (struct frame *frame, uint32_t attribute);
void frame_set_attribute (struct frame *frame, uint32_t attribute, bool on);

void frame_set_mmap (struct frame *frame, mmapid_t id, uint32_t offset,
                     uint32_t bytes_to_read);
void frame_set_zero (struct frame *frame);
void frame_set_swap (struct frame *frame);
#endif
