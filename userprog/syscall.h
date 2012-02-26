#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void filesys_free_open_files (struct thread *t);
const char* filesys_get_filename_from_fd (int fd);
void syscall_init (void);
int syscall_open (const char *file);
#endif /* userprog/syscall.h */
