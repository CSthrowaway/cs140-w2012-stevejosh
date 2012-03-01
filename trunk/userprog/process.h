#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct mmap_table_entry
  {
    struct list_elem elem;
    mmapid_t id;
    int fd;
  };

tid_t process_execute (const char *file_name);
void process_init (void);
void process_release (int exit_code);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

mmapid_t process_add_mmap_from_name (const char *file_name);
mmapid_t process_add_mmap_from_fd (int fd);
int process_get_mmap_fd (mmapid_t mapid);
bool check_mmap_pages_available (uint32_t vaddr, uint32_t finalAddress);
bool process_create_mmap_pages (int mmapid, void* vaddr);
void process_write_mmap_to_file (mapid_t mapping);
void process_remove_mmap_pages (mapid_t mapping);

#endif /* userprog/process.h */
