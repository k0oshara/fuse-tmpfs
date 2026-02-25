#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>

#include "fuse_tmpfs.h"

static fs_t g;

static void lg(const char* op, const char* fmt, ...) {
  if (!g.lg) return;
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  fprintf(stderr, "[tmpfs] %ld.%03ld %s: ", (long)ts.tv_sec, ts.tv_nsec / 1000000, op);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  fflush(stderr);
}

// when changing
static void st_touch_mctime(struct stat* st) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  st->st_mtim = ts;
  st->st_ctim = ts;
}

// when read
static void st_touch_atime(struct stat* st) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  st->st_atim = ts;
}

static inode* inode_new(in_type type, mode_t perm, uid_t uid, gid_t gid) {
  inode* n = (inode*)calloc(1, sizeof(*n));
  if (!n) return NULL;

  n->id = g.next_id++;
  n->type = type;

  memset(&n->st, 0, sizeof(n->st));
  n->st.st_uid = uid;
  n->st.st_gid = gid;

  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  n->st.st_atim = ts;
  n->st.st_mtim = ts;
  n->st.st_ctim = ts;

  if (type == IN_DIR) {
    n->st.st_mode = S_IFDIR | (perm & 0777); // 0777_8 = 111111111_2
    n->st.st_nlink = 2;
    n->st.st_size = 0;
  }
  else {
    n->st.st_mode = S_IFREG | (perm & 0777);
    n->st.st_nlink = 1;
    n->st.st_size = 0;
  }

  n->next = g.head;
  g.head = n;
  return n;
}

static void inode_free_one(inode* n) {
  if (!n) return;
  for (size_t i = 0; i < n->dn; i++) free(n->de[i].name);
  free(n->de);
  free(n->data);
  free(n);
}

static inode* dir_lookup(inode* d, const char* name) {
  if (!d || d->type != IN_DIR) return NULL;
  for (size_t i = 0; i < d->dn; i++) {
    if (strcmp(d->de[i].name, name) == 0) return d->de[i].node;
  }
  return NULL;
}

static int dir_add(inode* d, const char* name, inode* child) {
  if (!child || !name || !*name) return -EINVAL;
  if (!d || d->type != IN_DIR) return -ENOTDIR;
  if (dir_lookup(d, name)) return -EEXIST;

  if (d->dn == d->dc) {
    size_t nc = d->dc ? d->dc * 2 : 8;
    dent* nd = (dent*)realloc(d->de, nc * sizeof(*nd));
    if (!nd) return -ENOMEM;
    d->de = nd;
    d->dc = nc;
  }

  d->de[d->dn].name = strdup(name);
  if (!d->de[d->dn].name) return -ENOMEM;
  d->de[d->dn].node = child;
  d->dn++;

  child->parent = d;

  if (child->type == IN_DIR) d->st.st_nlink++;
  st_touch_mctime(&d->st);
  return 0;
}

static int dir_remove(inode* d, const char* name, inode** out_child) {
  if (!d || !name) return -EINVAL;
  if (d->type != IN_DIR) return -ENOTDIR;
  for (size_t i = 0; i < d->dn; i++) {
    if (strcmp(d->de[i].name, name) == 0) {
      inode* ch = d->de[i].node;
      free(d->de[i].name);
      d->de[i] = d->de[d->dn - 1];
      d->dn--;

      if (ch && ch->type == IN_DIR) d->st.st_nlink--;
      st_touch_mctime(&d->st);

      if (out_child) *out_child = ch;
      return 0;
    }
  }
  return -ENOENT;
}

static int path_resolve(const char* path, inode** out) {
  if (!path || !out) return -EINVAL;
  if (strcmp(path, "/") == 0) {
    *out = g.root;
    return 0;
  }
  if (path[0] != '/') return -EINVAL;

  char* tmp = strdup(path);
  if (!tmp) return -ENOMEM;

  inode* cur = g.root;
  char* save = NULL;
  char* tok = strtok_r(tmp + 1, "/", &save);
  while (tok) {
    if (cur->type != IN_DIR) { free(tmp); return -ENOTDIR; }
    inode* nx = dir_lookup(cur, tok);
    if (!nx) { free(tmp); return -ENOENT; }
    cur = nx;
    tok = strtok_r(NULL, "/", &save);
  }

  free(tmp);
  *out = cur;
  return 0;
}

static int path_parent(const char* path, inode** out_dir, char** out_name) {
  if (!path || !out_dir || !out_name) return -EINVAL;
  if (strcmp(path, "/") == 0) return -EINVAL;
  if (path[0] != '/') return -EINVAL;

  const char* last = strrchr(path, '/');
  if (!last) return -EINVAL;

  const char* name = last + 1;
  if (!*name) return -EINVAL;

  char* pname = strdup(name);
  if (!pname) return -ENOMEM;

  inode* par = NULL;
  if (last == path) {
    par = g.root;
  }
  else {
    size_t plen = (size_t)(last - path);
    char* pp = (char*)malloc(plen + 1);
    if (!pp) { free(pname); return -ENOMEM; }
    memcpy(pp, path, plen);
    pp[plen] = 0;

    int r = path_resolve(pp, &par);
    free(pp);
    if (r != 0) { free(pname); return r; }
  }

  if (par->type != IN_DIR) { free(pname); return -ENOTDIR; }

  *out_dir = par;
  *out_name = pname;
  return 0;
}

/* -------- FUSE callbacks -------- */

static int op_getattr(const char* path, struct stat* st, struct fuse_file_info* fi) {
  (void)fi;
  pthread_mutex_lock(&g.mu);
  inode* n = NULL;
  int r = path_resolve(path, &n);
  if (r == 0) *st = n->st;
  pthread_mutex_unlock(&g.mu);
  lg("getattr", "path=%s r=%d size=%ld mode=%o", path, r, r == 0 ? (long)st->st_size : -1L, r == 0 ? (unsigned)(st->st_mode & 07777) : 0U);
  return r;
}

static int op_opendir(const char* path, struct fuse_file_info* fi) {
  pthread_mutex_lock(&g.mu);
  inode* d = NULL;
  int r = path_resolve(path, &d);
  if (r != 0) { pthread_mutex_unlock(&g.mu); lg("opendir", "path=%s r=%d", path, r); return r; }
  if (d->type != IN_DIR) { pthread_mutex_unlock(&g.mu); lg("opendir", "path=%s r=-ENOTDIR", path); return -ENOTDIR; }
  fi->fh = (uint64_t)(uintptr_t)d;
  pthread_mutex_unlock(&g.mu);
  lg("opendir", "path=%s r=0", path);
  return 0;
}

static int op_releasedir(const char* path, struct fuse_file_info* fi) {
  (void)fi;
  lg("releasedir", "path=%s r=0", path);
  return 0;
}

static int op_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                      off_t off, struct fuse_file_info* fi, enum fuse_readdir_flags flags) {
  (void)off; (void)flags;

  pthread_mutex_lock(&g.mu);

  inode* d = NULL;
  if (fi && fi->fh) d = (inode*)(uintptr_t)fi->fh;
  else {
    int r0 = path_resolve(path, &d);
    if (r0 != 0) { pthread_mutex_unlock(&g.mu); lg("readdir", "path=%s r=%d", path, r0); return r0; }
  }

  if (!d || d->type != IN_DIR) { pthread_mutex_unlock(&g.mu); lg("readdir", "path=%s r=-ENOTDIR", path); return -ENOTDIR; }

  filler(buf, ".", NULL, 0, 0);
  filler(buf, "..", NULL, 0, 0);

  for (size_t i = 0; i < d->dn; i++) {
    struct stat st = d->de[i].node->st;
    filler(buf, d->de[i].name, &st, 0, 0);
  }

  st_touch_atime(&d->st);
  size_t n = d->dn;
  pthread_mutex_unlock(&g.mu);
  lg("readdir", "path=%s r=0 entries=%zu", path, n);
  return 0;
}

static int op_mkdir(const char* path, mode_t mode) {
  pthread_mutex_lock(&g.mu);

  inode* par = NULL;
  char* name = NULL;
  int r = path_parent(path, &par, &name);
  if (r != 0) { pthread_mutex_unlock(&g.mu); lg("mkdir", "path=%s r=%d", path, r); return r; }

  if (dir_lookup(par, name)) { free(name); pthread_mutex_unlock(&g.mu); lg("mkdir", "path=%s r=-EEXIST", path); return -EEXIST; }

  struct fuse_context* ctx = fuse_get_context();
  mode_t m = (mode ? (mode & 0777) : 0755);
  m &= ~(ctx ? ctx->umask : 0022);

  inode* nd = inode_new(IN_DIR, m, ctx ? ctx->uid : getuid(), ctx ? ctx->gid : getgid());
  if (!nd) { free(name); pthread_mutex_unlock(&g.mu); lg("mkdir", "path=%s r=-ENOMEM", path); return -ENOMEM; }

  r = dir_add(par, name, nd);
  free(name);

  pthread_mutex_unlock(&g.mu);
  lg("mkdir", "path=%s r=%d mode=%o", path, r, (unsigned)m);
  return r;
}

static int op_rmdir(const char* path) {
  pthread_mutex_lock(&g.mu);

  inode* par = NULL;
  char* name = NULL;
  int r = path_parent(path, &par, &name);
  if (r != 0) { pthread_mutex_unlock(&g.mu); lg("rmdir", "path=%s r=%d", path, r); return r; }

  inode* ch = dir_lookup(par, name);
  if (!ch) { free(name); pthread_mutex_unlock(&g.mu); lg("rmdir", "path=%s r=-ENOENT", path); return -ENOENT; }
  if (ch->type != IN_DIR) { free(name); pthread_mutex_unlock(&g.mu); lg("rmdir", "path=%s r=-ENOTDIR", path); return -ENOTDIR; }
  if (ch->dn != 0) { free(name); pthread_mutex_unlock(&g.mu); lg("rmdir", "path=%s r=-ENOTEMPTY", path); return -ENOTEMPTY; }

  r = dir_remove(par, name, NULL);
  free(name);

  pthread_mutex_unlock(&g.mu);
  lg("rmdir", "path=%s r=%d", path, r);
  return r;
}

// remove a file
static int op_unlink(const char* path) {
  pthread_mutex_lock(&g.mu);

  inode* par = NULL;
  char* name = NULL;
  int r = path_parent(path, &par, &name);
  if (r != 0) { pthread_mutex_unlock(&g.mu); lg("unlink", "path=%s r=%d", path, r); return r; }

  inode* ch = dir_lookup(par, name);
  if (!ch) { free(name); pthread_mutex_unlock(&g.mu); lg("unlink", "path=%s r=-ENOENT", path); return -ENOENT; }
  if (ch->type != IN_FILE) { free(name); pthread_mutex_unlock(&g.mu); lg("unlink", "path=%s r=-EISDIR", path); return -EISDIR; }

  r = dir_remove(par, name, NULL);
  free(name);

  pthread_mutex_unlock(&g.mu);
  lg("unlink", "path=%s r=%d", path, r);
  return r;
}

static int op_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
  pthread_mutex_lock(&g.mu);

  inode* par = NULL;
  char* name = NULL;
  int r = path_parent(path, &par, &name);
  if (r != 0) { pthread_mutex_unlock(&g.mu); lg("create", "path=%s r=%d", path, r); return r; }

  if (dir_lookup(par, name)) { free(name); pthread_mutex_unlock(&g.mu); lg("create", "path=%s r=-EEXIST", path); return -EEXIST; }

  struct fuse_context* ctx = fuse_get_context();
  mode_t m = (mode ? (mode & 0777) : 0644);
  m &= ~(ctx ? ctx->umask : 0022);

  inode* nf = inode_new(IN_FILE, m, ctx ? ctx->uid : getuid(), ctx ? ctx->gid : getgid());
  if (!nf) { free(name); pthread_mutex_unlock(&g.mu); lg("create", "path=%s r=-ENOMEM", path); return -ENOMEM; }

  r = dir_add(par, name, nf);
  free(name);
  if (r != 0) { pthread_mutex_unlock(&g.mu); lg("create", "path=%s r=%d", path, r); return r; }

  fi->fh = (uint64_t)(uintptr_t)nf;
  pthread_mutex_unlock(&g.mu);
  lg("create", "path=%s r=0 mode=%o", path, (unsigned)m);
  return 0;
}

static int op_open(const char* path, struct fuse_file_info* fi) {
  pthread_mutex_lock(&g.mu);

  inode* n = NULL;
  int r = path_resolve(path, &n);
  if (r != 0) { pthread_mutex_unlock(&g.mu); lg("open", "path=%s r=%d", path, r); return r; }
  if (n->type != IN_FILE) { pthread_mutex_unlock(&g.mu); lg("open", "path=%s r=-EISDIR", path); return -EISDIR; }

  fi->fh = (uint64_t)(uintptr_t)n;
  pthread_mutex_unlock(&g.mu);
  lg("open", "path=%s r=0", path);
  return 0;
}

static int op_release(const char* path, struct fuse_file_info* fi) {
  (void)fi;
  lg("release", "path=%s r=0", path);
  return 0;
}

static int op_read(const char* path, char* buf, size_t size, off_t off, struct fuse_file_info* fi) {
  pthread_mutex_lock(&g.mu);

  inode* n = (inode*)(uintptr_t)fi->fh;
  if (!n || n->type != IN_FILE) { pthread_mutex_unlock(&g.mu); lg("read", "path=%s off=%ld size=%zu r=-EBADF", path, (long)off, size); return -EBADF; }
  if (off < 0) { pthread_mutex_unlock(&g.mu); lg("read", "path=%s off=%ld size=%zu r=-EINVAL", path, (long)off, size); return -EINVAL; }

  size_t fsz = (size_t)n->st.st_size;
  if ((size_t)off >= fsz) { pthread_mutex_unlock(&g.mu); lg("read", "path=%s off=%ld size=%zu r=0", path, (long)off, size); return 0; }

  size_t can = fsz - (size_t)off;
  if (size > can) size = can;

  memcpy(buf, n->data + off, size);
  st_touch_atime(&n->st);

  pthread_mutex_unlock(&g.mu);
  lg("read", "path=%s off=%ld size=%zu r=%zu", path, (long)off, size, size);
  return (int)size;
}

static int op_write(const char* path, const char* buf, size_t size, off_t off, struct fuse_file_info* fi) {
  pthread_mutex_lock(&g.mu);

  inode* n = (inode *)(uintptr_t)fi->fh;
  if (!n || n->type != IN_FILE) { pthread_mutex_unlock(&g.mu); lg("write", "path=%s off=%ld size=%zu r=-EBADF", path, (long)off, size); return -EBADF; }
  if (off < 0) { pthread_mutex_unlock(&g.mu); lg("write", "path=%s off=%ld size=%zu r=-EINVAL", path, (long)off, size); return -EINVAL; }

  size_t need = (size_t)off + size;
  if (need > n->cap) {
    size_t nc = n->cap ? n->cap : 4096;
    while (nc < need) nc *= 2;
    uint8_t* nd = (uint8_t *)realloc(n->data, nc);
    if (!nd) { pthread_mutex_unlock(&g.mu); lg("write", "path=%s off=%ld size=%zu r=-ENOMEM", path, (long)off, size); return -ENOMEM; }
    if (nc > n->cap) memset(nd + n->cap, 0, nc - n->cap);
    n->data = nd;
    n->cap = nc;
  }

  memcpy(n->data + off, buf, size);
  if (need > (size_t)n->st.st_size) n->st.st_size = (off_t)need;
  st_touch_mctime(&n->st);

  pthread_mutex_unlock(&g.mu);
  lg("write", "path=%s off=%ld size=%zu r=%zu new_size=%ld", path, (long)off, size, size, (long)n->st.st_size);
  return (int)size;
}

static int op_truncate(const char* path, off_t size, struct fuse_file_info* fi) {
  (void)fi;
  if (size < 0) { lg("truncate", "path=%s size=%ld r=-EINVAL", path, (long)size); return -EINVAL; }

  pthread_mutex_lock(&g.mu);

  inode* n = NULL;
  int r = path_resolve(path, &n);
  if (r != 0) { pthread_mutex_unlock(&g.mu); lg("truncate", "path=%s size=%ld r=%d", path, (long)size, r); return r; }
  if (n->type != IN_FILE) { pthread_mutex_unlock(&g.mu); lg("truncate", "path=%s size=%ld r=-EISDIR", path, (long)size); return -EISDIR; }

  size_t ns = (size_t)size;
  if (ns > n->cap) {
    size_t nc = n->cap ? n->cap : 4096;
    while (nc < ns) nc *= 2;
    uint8_t* nd = (uint8_t *)realloc(n->data, nc);
    if (!nd) { pthread_mutex_unlock(&g.mu); lg("truncate", "path=%s size=%ld r=-ENOMEM", path, (long)size); return -ENOMEM; }
    if (nc > n->cap) memset(nd + n->cap, 0, nc - n->cap);
    n->data = nd;
    n->cap = nc;
  }

  if (ns > (size_t)n->st.st_size) {
    memset(n->data + n->st.st_size, 0, ns - (size_t)n->st.st_size);
  }
  n->st.st_size = (off_t)ns;
  st_touch_mctime(&n->st);

  pthread_mutex_unlock(&g.mu);
  lg("truncate", "path=%s size=%ld r=0", path, (long)size);
  return 0;
}

static int op_utimens(const char* path, const struct timespec tv[2], struct fuse_file_info* fi) {
  (void)fi;
  pthread_mutex_lock(&g.mu);

  inode* n = NULL;
  int r = path_resolve(path, &n);
  if (r == 0) {
    n->st.st_atim = tv[0];
    n->st.st_mtim = tv[1];
    n->st.st_ctim = tv[1];
  }

  pthread_mutex_unlock(&g.mu);
  lg("utimens", "path=%s r=%d", path, r);
  return r;
}

static int op_rename(const char* from, const char* to, unsigned int flags) {
  pthread_mutex_lock(&g.mu);

  if (flags != 0) { pthread_mutex_unlock(&g.mu); lg("rename", "from=%s to=%s flags=%u r=-EINVAL", from, to, flags); return -EINVAL; }

  inode *p1 = NULL, *p2 = NULL;
  char *n1 = NULL, *n2 = NULL;

  int r = path_parent(from, &p1, &n1);
  if (r != 0) { pthread_mutex_unlock(&g.mu); lg("rename", "from=%s to=%s r=%d", from, to, r); return r; }
  r = path_parent(to, &p2, &n2);
  if (r != 0) { free(n1); pthread_mutex_unlock(&g.mu); lg("rename", "from=%s to=%s r=%d", from, to, r); return r; }

  if (p1 == p2 && strcmp(n1, n2) == 0) { free(n1); free(n2); pthread_mutex_unlock(&g.mu); lg("rename", "from=%s to=%s r=0 (same file)", from, to); return 0; }

  inode* src = dir_lookup(p1, n1);
  if (!src) { free(n1); free(n2); pthread_mutex_unlock(&g.mu); lg("rename", "from=%s to=%s r=-ENOENT", from, to); return -ENOENT; }

  inode* dst = dir_lookup(p2, n2);

  inode* dst_removed = NULL;
  int removed_dst = 0;

  if (dst) {
    if (dst->type == IN_DIR) {
      if (src->type != IN_DIR) { free(n1); free(n2); pthread_mutex_unlock(&g.mu); lg("rename", "from=%s to=%s r=-EISDIR", from, to); return -EISDIR; }
      if (dst->dn != 0) { free(n1); free(n2); pthread_mutex_unlock(&g.mu); lg("rename", "from=%s to=%s r=-ENOTEMPTY", from, to); return -ENOTEMPTY; }
    }
    else { // dst is file
      if (src->type == IN_DIR) { free(n1); free(n2); pthread_mutex_unlock(&g.mu); lg("rename", "from=%s to=%s r=-ENOTDIR", from, to); return -ENOTDIR; }
    }

    r = dir_remove(p2, n2, &dst_removed);
    if (r != 0 || dst_removed != dst) { free(n1); free(n2); pthread_mutex_unlock(&g.mu); lg("rename", "from=%s to=%s r=-EIO (remove dst failed)", from, to); return -EIO; }
    removed_dst = 1;
  }

  inode* src_removed = NULL;
  r = dir_remove(p1, n1, &src_removed);
  if (r != 0 || src_removed != src) {
    if (removed_dst && dst_removed) (void)dir_add(p2, n2, dst_removed);
    free(n1); free(n2); pthread_mutex_unlock(&g.mu); lg("rename", "from=%s to=%s r=-EIO (remove src failed, rallback)", from, to);
    return -EIO;
  }

  r = dir_add(p2, n2, src);
  if (r != 0) {
    (void)dir_add(p1, n1, src);
    if (removed_dst && dst_removed) (void)dir_add(p2, n2, dst_removed);
    free(n1); free(n2); pthread_mutex_unlock(&g.mu); lg("rename", "from=%s to=%s r=%d (add failed, rollback)", from, to, r);
    return r;
  }

  free(n1);
  free(n2);

  pthread_mutex_unlock(&g.mu);
  lg("rename", "from=%s to=%s r=0 replaced=%d", from, to, removed_dst);
  return r;
}

static void* op_init(struct fuse_conn_info* conn, struct fuse_config* cfg) {
  (void)conn;
  cfg->kernel_cache = 0;
  lg("init", "r=0");
  return NULL;
}

static void op_destroy(void* userdata) {
  (void)userdata;
  pthread_mutex_lock(&g.mu);

  inode* cur = g.head;
  while (cur) {
    inode* nx = cur->next;
    inode_free_one(cur);
    cur = nx;
  }
  g.head = NULL;
  g.root = NULL;

  pthread_mutex_unlock(&g.mu);
  lg("destroy", "r=0");
}

struct fuse_operations fuse_tmpfs_ops = {
  .init       = op_init,
  .destroy    = op_destroy,

  .getattr    = op_getattr,

  .opendir    = op_opendir,
  .readdir    = op_readdir,
  .releasedir = op_releasedir,

  .mkdir      = op_mkdir,
  .rmdir      = op_rmdir,

  .create     = op_create,
  .open       = op_open,
  .release    = op_release,

  .read       = op_read,
  .write      = op_write,
  .truncate   = op_truncate,
  .unlink     = op_unlink,

  .utimens    = op_utimens,
  .rename     = op_rename,
};

int fuse_tmpfs_init(void) {
  memset(&g, 0, sizeof(g));
  if (pthread_mutex_init(&g.mu, NULL) != 0) return -1;
  g.next_id = 2;

  const char* e = getenv("FUSE_TMPFS_LOG");
  g.lg = (!e || strcmp(e, "0") != 0);

  uid_t uid = getuid();
  gid_t gid = getgid();

  pthread_mutex_lock(&g.mu);
  g.root = inode_new(IN_DIR, 0755, uid, gid);
  if (!g.root) { pthread_mutex_unlock(&g.mu); return -1; }
  g.root->parent = g.root;
  pthread_mutex_unlock(&g.mu);

  lg("init", "log=%d", g.lg);
  return 0;
}
