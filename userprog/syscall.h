#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void filesys_free_open_files (struct thread *t);
void syscall_init (void);
#endif /* userprog/syscall.h */
