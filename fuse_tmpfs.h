#ifndef FUSE_TMPFS_H
#define FUSE_TMPFS_H

#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>

extern struct fuse_operations fuse_tmpfs_ops;

typedef enum { IN_DIR = 1, IN_FILE = 2 } in_type;

typedef struct inode inode;

// directory entrie
typedef struct {
  char *name;
  inode *node;
} dent;

struct inode {
  uint64_t id;
  in_type type;
  struct stat st;

  inode *parent;

  dent *de;
  size_t dn; // directory entries number
  size_t dc; // directory capacity

  uint8_t *data; // if type == IN_FILE
  size_t cap;

  inode *next;
};

typedef struct {
  pthread_mutex_t mu;
  inode *root;
  inode *head;
  uint64_t next_id;
  int lg;
} fs_t;

int fuse_tmpfs_init(void);

#endif
