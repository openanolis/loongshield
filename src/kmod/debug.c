#include "debug.h"
#include <linux/slab.h>

#ifdef DEBUG

static atomic_t alloc_count;

void *os_kmalloc(size_t size, gfp_t flags)
{
    void *ret = kmalloc(size, flags);
    if (ret)
        atomic_inc(&alloc_count);
    return ret;
}

void *os_kzalloc(size_t size, gfp_t flags)
{
    void *ret = kzalloc(size, flags);
    if (ret)
        atomic_inc(&alloc_count);
    return ret;
}

void os_kfree(const void *p)
{
    if (p)
        atomic_dec(&alloc_count);
    return kfree(p);
}

void __kmem_alloc_sanity(void)
{
    int count = atomic_read(&alloc_count);
    __log_warn("kmem: alloc_count = %d\n", count);
    BUG_ON(count != 0);
}

#endif
