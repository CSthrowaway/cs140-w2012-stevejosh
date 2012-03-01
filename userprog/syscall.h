#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

void filesys_free_open_files (struct thread *t);
const char* filesys_get_filename_from_fd (int fd);
void syscall_init (void);
int syscall_open (const char *file);
//int lock_filesys (void);
//int unlock_filesys (void);

int fd_open (const char *file);
int fd_read (int fd, void *buffer, unsigned size);
int fd_write (int fd, const void *buffer, unsigned size);
int fd_filesize (int fd);
void fd_seek (int fd, unsigned position);

#endif /* userprog/syscall.h */
