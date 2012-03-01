#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/page.h"

void
page_init (void)
{
  // TODO : Anything here? If so, call it from syscall.c
}

/* Hash function for page table entries (uses virtual address). */
static unsigned
page_table_entry_hash (const struct hash_elem *e, void *aux UNUSED)
{
  struct page_table_entry *p = hash_entry(e, struct page_table_entry, h_elem);
  return (unsigned)p->vaddr;
}

/* Comparator for page table entries (uses virtual address). */
static bool
page_table_entry_less (const struct hash_elem *a,
                       const struct hash_elem *b,
                       void *aux UNUSED)
{
  struct page_table_entry *a_e = hash_entry(a, struct page_table_entry, h_elem);
  struct page_table_entry *b_e = hash_entry(b, struct page_table_entry, h_elem);
  return (a_e->vaddr < b_e->vaddr);
}

/* Returns a new, empty supplemental page table. */
struct page_table*
page_table_create (void)
{
  struct page_table *t = malloc (sizeof(struct page_table));
  if (t == NULL)
    PANIC ("page_table_create: unable to allocate supplemental page table");
  
  hash_init (&t->table, page_table_entry_hash, page_table_entry_less, NULL);
  lock_init (&t->lock);
  return t;
}

void
page_table_free (struct page_table *ptable)
{
  // TODO - Free up all of the entries
  free (ptable);
}

/* Look up the given virtual address in the given page table, returning the
   page_table_entry which owns the page that contains the address. Returns
   NULL if the virtual address is unmapped. */
struct page_table_entry*
page_table_lookup (struct page_table *ptable, const void* vaddr)
{
  vaddr = pg_round_down (vaddr);
  struct page_table_entry e;
  e.vaddr = (void *)vaddr;
  
  struct hash_elem *found;
  found = hash_find (&ptable->table, &e.h_elem);

  if (found == NULL)
    return NULL;

  return hash_entry (found, struct page_table_entry, h_elem);
}


/* Look up the given virtual address in the given page table, returning either
   the address (if it exists inside the page table), or NULL if the address
   is not contained in any virtual page in the page table. */   
void*
page_table_translate (struct page_table *ptable, const void* vaddr)
  {
    struct page_table_entry *pte = page_table_lookup (ptable, vaddr);
    return (pte == NULL ) ? NULL : vaddr;
  }

/* NOTE : Assumes that synchronization has already been taken care of (e.g.,
          the caller has already acquired this page table's lock. */
struct page_table_entry*
page_table_add_entry (struct page_table *ptable, const void* vaddr,
                      struct frame *frame)
{
  ASSERT (vaddr == pg_round_down (vaddr));

  struct page_table_entry *entry = malloc (sizeof(struct page_table_entry));
  if (entry == NULL)
    PANIC ("page_table_add_entry: unable to allocate page table entry");

  entry->vaddr = (void *)vaddr;
  entry->frame = frame;
  entry->thread = thread_current ();
  hash_insert (&ptable->table, &entry->h_elem);
  list_push_back (&frame->users, &entry->l_elem);
  return entry;
}

/* Given a supplemental page table entry that contains an active frame, install
   the physical frame in the corresponding thread's hardware page table, making
   the supplemental page table entry active. */
void
page_table_entry_activate (struct page_table_entry *pte)
{
  ASSERT (pte->frame->paddr != NULL);
  pagedir_set_page (pte->thread->pagedir,
                    pte->vaddr,
                    pte->frame->paddr,
                    !(pte->frame->status & FRAME_READONLY));
}

/* Given a supplemental page table entry that contains an active frame,
   uninstall the physical frame from the corresponding thread's hardware page
   table, such that subsequent accesses to the page given by pte->vaddr will
   fault. */
void
page_table_entry_deactivate (struct page_table_entry *pte)
{
  ASSERT (pte->frame->paddr != NULL);
  pagedir_clear_page (pte->thread->pagedir, pte->vaddr);
}

void
page_table_entry_load (struct page_table_entry *pte)
{
  if (pte->frame->paddr == NULL)
    {
      frame_page_in (pte->frame);
      page_table_entry_activate (pte);
    }
}

void
page_table_entry_clear (struct page_table_entry *pte)
{
  pagedir_clear_page (pte->thread->pagedir, pte->vaddr);
  list_remove (&pte->l_elem);
  if (list_empty (&pte->frame->users))
    frame_free (pte->frame);
    
  pte->frame = NULL;
  pte->vaddr = NULL;
}

/* Removes the given element from the page table. */
void 
page_table_entry_remove (struct page_table_entry *pte)
{
  struct page_table* pt = pte->thread->page_table;
  hash_delete (&pt->table, &pte->h_elem);
  free (pte);
}
