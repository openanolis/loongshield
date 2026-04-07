#ifndef SYSMON_RWLOCK_H
#define SYSMON_RWLOCK_H

#include <linux/rwlock.h>

struct rw_lock {
    rwlock_t lock;
    enum {
        LS_free,
        LS_read,
        LS_write
    } state;
};

#define RW_LOCK_UNLOCKED(x)             \
    {                                   \
        .lock = __RW_LOCK_UNLOCKED(x),  \
        .state = LS_free                \
    }

#define DEFINE_RW_LOCK(x) struct rw_lock x = RW_LOCK_UNLOCKED(x)

static inline int __rwlock_init(struct rw_lock *l)
{
    l->state = LS_free;
    rwlock_init(&l->lock);
    return 0;
}

static inline void __rwlock_deinit(struct rw_lock *l)
{
}

static inline void __rwlock_lock_read(struct rw_lock *l)
{
    read_lock(&l->lock);
    l->state = LS_read;
}

static inline void __rwlock_lock_write(struct rw_lock *l)
{
    write_lock(&l->lock);
    l->state = LS_write;
}

static inline void __rwlock_unlock(struct rw_lock *l)
{
    if (l->state == LS_read) {
        read_unlock(&l->lock);
    } else if (l->state == LS_write) {
        l->state = LS_free;
        write_unlock(&l->lock);
    }
}

#endif /* ! SYSMON_RWLOCK_H */
