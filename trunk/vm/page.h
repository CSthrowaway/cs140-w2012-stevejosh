#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "vm/frame.h"

/* page_table_entry defines the information that will be contained in the
   supplemental page table. Each entry will be inserted into a process'
   supplemental table, and is responsible for keeping track of a single
   page of virtual memory. */
struct page_table_entry
  {
    struct hash_elem h_elem;      /* For wiring into a hash table. */
    struct list_elem l_elem;      /* For wiring into a frame's user list. */
    void* vaddr;                  /* Base virtual address of this page. */
    struct frame* frame;          /* Pointer to this page's frame element. */
    struct thread* thread;        /* Pointer to the relevant thread
				     containing the current page directory
				     and page table. */
  };

/* page_table defines the supplemental page table contained in each process.
   Note that each process owns a page table lock for synchronization of paging
   during fault-handling. */
struct page_table
  {
    struct hash table;
    struct lock lock;
  };

void page_init (void);
struct page_table* page_table_create (void);
void page_table_free (struct page_table *ptable);

struct page_table_entry*
page_table_lookup (struct page_table *ptable, void* vaddr);

struct page_table_entry*
page_table_add_entry (struct page_table *ptable, void* vaddr,
                      struct frame *frame);

#endif
