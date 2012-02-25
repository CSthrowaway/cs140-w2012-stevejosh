#include "lib/kernel/hash.h"
#include "threads/synch.h"

/* Below are the various status bits that may reside in a page_status
   bitfield. Some are mutually exclusive, such as PAGE_ZERO, PAGE_SWAP,
   and PAGE_FILE, while some may be mixed (for example, PAGE_SWAP,
   PAGE_PINNED, PAGE_RESIDENT may all be on at the same time). */
#define PAGE_ZERO 0x1             /* Set when the page is zero-filled. */
#define PAGE_SWAP 0x2             /* Set when the page is to be loaded and
                                     saved to/from a swap slot. */
#define PAGE_FILE 0x4             /* Set when the page is to be loaded and
                                     saved to/from a file. */
#define PAGE_PINNED 0x8           /* Set to protect page from eviction. */
#define PAGE_RESIDENT 0x10        /* Set when the page is mapped to a frame. */
#define PAGE_READONLY 0x20        /* Set when the page is not writeable. */

typedef uint32_t page_status;

/* sup_table_entry defines the information that will be contained in the
   supplementary page table. Each entry will be inserted into a process'
   supplementary table, and is responsible for keeping track of a single
   page of virtual memory. */
struct sup_table_entry
  {
    struct hash_elem h_elem;      /* For wiring into a hash table. */
    struct list_elem l_elem;      /* For wiring into a frame's user list. */
    void* vaddr;                  /* Base virtual address of this page. */
    page_status status;           /* Indicates where the page can be found. */
    void* aux;                    /* Auxillary data (could be swap location,
                                     file name, etc.) */
    struct frame_elem* frame;     /* Pointer to this page's frame element. */
  };

/* sup_table defines the supplementary page table contained in each process.
   Note that each process own a sup_table lock for synchronization of paging
   during fault-handling. */
struct sup_table
  {
    struct hash table;
    struct lock lock;
  };

void page_init (void);
