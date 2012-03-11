#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"
#include "filesys/file.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14
#define FILE_PATH_MAX 256

struct inode;

/* Opening and closing directories. */
bool dir_create (block_sector_t sector, size_t entry_cnt);
struct file *dir_open_root (void);
struct inode *dir_get_inode (struct file *);
bool dir_is_empty (struct file *dir);

/* Reading and writing. */
int dir_lookup (struct file *dir, const char *name);
bool dir_add (struct file *dir, const char *name, block_sector_t);
bool dir_remove (struct file *dir, const char *name);
bool dir_readdir (struct file *dir, char *buf);

#endif /* filesys/directory.h */
