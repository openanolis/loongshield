#ifndef SYSMON_SECURITYFS_H
#define SYSMON_SECURITYFS_H

#ifdef FILTER_PROFILE

#include <linux/fs.h>
#undef LIST_HEAD
#include "queue.h"
#include "ctor.h"

struct fs_ent {
    const char *name;
    const struct file_operations *fops;
    struct dentry *dentry;
    TAILQ_ENTRY(fs_ent) list;
};

void fsent_register(struct fs_ent *ent);

#define SYSFS_ENT_DEFINE(name, show)                                     \
static int __open_ ## name(struct inode *inode, struct file *filp) {     \
    return single_open(filp, show, NULL);                                \
}                                                                        \
static const struct file_operations __fops_ ## name = {                  \
    .open    = __open_ ## name,                                          \
    .read    = seq_read,                                                 \
    .llseek  = seq_lseek,                                                \
    .release = single_release                                            \
};                                                                       \
static struct fs_ent __ent_ ## name = { #name, &__fops_ ## name, NULL }; \
static void __register_fsent_ ## name(void) {                            \
    fsent_register(&__ent_ ## name);                                     \
}                                                                        \
__initcall(__register_fsent_ ## name)

int securityfs_init(void);
void securityfs_exit(void);

#else /* FILTER_PROFILE */

#define SYSFS_ENT_DEFINE(name, show)

static inline int securityfs_init(void)
{
    return 0;
}

static inline void securityfs_exit(void) { }

#endif


#endif /* !SYSMON_SECURITYFS_H */
