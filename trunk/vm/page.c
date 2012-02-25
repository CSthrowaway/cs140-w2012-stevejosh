#include "threads/malloc.h"
#include "threads/synch.h"
#include "vm/page.h"

void
page_init (void)
{
  // TODO : Anything here?
}

struct sup_table*
sup_table_create (void)
{
  struct sup_table *t = malloc (sizeof(struct sup_table));
  if (t == NULL)
    PANIC ("sub_table_create: unable to allocate supplementary table");
  
  lock_init (&t->lock);
  return t;
}

