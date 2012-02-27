#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/list.h"
#include "vm/page.h"

/* Below are the various status bits that may reside in a page_status
   bitfield. Some are mutually exclusive, such as FRAME_ZERO, FRAME_SWAP,
   and FRAME_FILE, while some may be mixed (for example, FRAME_SWAP,
   FRAME_PINNED, FRAME_RESIDENT may all be on at the same time). */
#define FRAME_ZERO 0x1             /* Set when the frame is zero-filled. */
#define FRAME_SWAP 0x2             /* Set when the frame is to be loaded and
                                      saved to/from a swap slot. */
#define FRAME_MMAP 0x4             /* Set when the frame is to be loaded and
                                      saved to/from a file. */
#define FRAME_PINNED 0x8           /* Set to protect frame from eviction. */
#define FRAME_READONLY 0x10        /* Set when the frame is not writeable. */

// Macros for checking particular status bits of a page_status
#define IS_FRAME_ZERO(x) ((x) & FRAME_ZERO)
#define IS_FRAME_SWAP(x) ((x) & FRAME_SWAP)
#define IS_FRAME_FILE(x) ((x) & FRAME_FILE)
#define IS_FRAME_PINNED(x) ((x) & FRAME_PINNED)
#define IS_FRAME_READONLY(x) ((x) & FRAME_READONLY)

typedef uint32_t frame_status;

typedef void* frame;

struct frame
  {
    void *paddr;                    /* Physical address of this frame. */
    frame_status status;
    uint32_t aux1;
    uint32_t aux2;
    uint32_t aux3;
    struct list_elem elem;          /* List element for allocated list. */
    struct list users;              /* List of all virtual pages using this
                                       physical frame (will usually be a
                                       single page). */
  };

// TODO REMOVE THIS
typedef uint32_t mmapid_t;

void frame_init (void);
struct frame *frame_alloc (void);
void frame_free (struct frame *frame);
void frame_page_in (struct frame *frame);

void frame_set_attribute (struct frame *frame, uint32_t attribute, bool on);

void frame_set_mmap (struct frame *frame, mmapid_t id, uint32_t offset,
                     uint32_t bytes_to_read);
void frame_set_zero (struct frame *frame);
void frame_set_swap (struct frame *frame);
#endif
