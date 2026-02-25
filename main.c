#include "fuse_tmpfs.h"

#include <stdio.h>

int main(int argc, char **argv) {
  if (fuse_tmpfs_init() != 0) {
    fprintf(stderr, "fuse_tmpfs_init failed\n");
    return 1;
  }
  return fuse_main(argc, argv, &fuse_tmpfs_ops, NULL);
}
