#include "debug.h"
#include <linux/poll.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include "securityfs.h"

#ifdef FILTER_PROFILE

static TAILQ_HEAD(, fs_ent) fsents = TAILQ_HEAD_INITIALIZER(fsents);

void fsent_register(struct fs_ent *ent)
{
    __log_info("fs_ent: %s\n", ent->name);
    TAILQ_INSERT_TAIL(&fsents, ent, list);
}

static struct dentry *dirent;

void securityfs_exit(void)
{
    struct fs_ent *ent;

    TAILQ_FOREACH(ent, &fsents, list) {
        if (ent->dentry)
            securityfs_remove(ent->dentry);
    }

    if (!IS_ERR_OR_NULL(dirent))
        securityfs_remove(dirent);
}

int securityfs_init(void)
{
    struct fs_ent *ent;
    void *key = ((unsigned char *)NULL) + 1/*SYSMON_FS_QUERY*/;

    dirent = securityfs_create_dir(BASENAME, NULL);
    if (IS_ERR_OR_NULL(dirent)) {
        __log_error("securityfs_create_dir(%s), err = %ld\n",
                    BASENAME, PTR_ERR(dirent));

        return (int)PTR_ERR(dirent);
    }

    TAILQ_FOREACH(ent, &fsents, list) {
        struct dentry *d;

        d = securityfs_create_file(ent->name, 0600, dirent, key, ent->fops);
        if (IS_ERR_OR_NULL(d)) {
            __log_error("securityfs_create_file(%s), err = %ld\n",
                        ent->name, PTR_ERR(d));

            securityfs_exit();
            return -EFAULT;
        }
        ent->dentry = d;
    }

    return 0;
}

#endif /* ! FILTER_PROFILE */
