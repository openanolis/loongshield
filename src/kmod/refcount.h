#ifndef KERN_REFCOUNT_H
#define KERN_REFCOUNT_H

#include "debug.h"
#include <linux/kernel.h>

#ifdef DEBUG
#define __breakpoint() BUG()
#else
#define __breakpoint() do {} while (0)
#endif

#define KASSERT(exp, msg)    \
    do {                     \
        if (!(exp)) {        \
            __log_error msg; \
        }                    \
    } while (0)


static inline void
refcount_init(atomic_t *count, long value)
{
    atomic_set(count, value);
}

static inline void
refcount_acquire(atomic_t *count)
{
    KASSERT(atomic_read(count) < UINT_MAX, ("refcount %p overflowed", count));
    atomic_inc(count);
}

static inline int
refcount_release(atomic_t *count)
{
    long n;
    n = atomic_dec_return(count);
    KASSERT(n >= 0, ("negative refcount %p", count));
    return (n == 0);
}

#endif /* ! KERN_REFCOUNT_H */
