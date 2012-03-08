#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#define MAX_STACK 1024 * 1024 * 10     /* The current stack limit is 10 MB. */

/* An mmap_table_entry contains the information required to create an
   mmap->fd mapping withing a process. These entries are inserted into the
   process' mmap_table to enable tracking of all of the process' outstanding
   mmaps. */
struct mmap_table_entry
  {
    struct list_elem elem;  /* List element for insertion into mmap_table. */
    mmapid_t id;            /* Per-process unique mmap id. */
    int fd;                 /* File descriptor for the file to which this mmap
                               is mapped. */
  };

tid_t process_execute (const char *file_name);
void process_init (void);
void process_release (int exit_code);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#ifdef VM
mmapid_t process_add_mmap_from_name (const char *file_name);
mmapid_t process_add_mmap_from_fd (int fd);
void process_remove_mmap (mmapid_t mapid);
int process_get_mmap_fd (mmapid_t mapid);

bool process_create_mmap_pages (mmapid_t mmapid, void *vaddr);
void process_write_mmap_to_file (mapid_t mapping);
#endif

#endif /* userprog/process.h */
