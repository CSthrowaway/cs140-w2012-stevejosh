#ifndef VM_SWAP_H
#define VM_SWAP_H

typedef uint32_t swapid_t;

void swap_init (void);
swapid_t swap_alloc (void);
void swap_free (swapid_t id);

void swap_read (swapid_t id, char *buf);
void swap_write (swapid_t id, const char *buf);

#endif
