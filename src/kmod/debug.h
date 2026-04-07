#ifndef SYSMON_DEBUG_H
#define SYSMON_DEBUG_H

#ifdef DEBUG

#define pr_fmt(fmt) fmt

#include <linux/printk.h>
#include <linux/module.h>
#include <linux/ratelimit.h>

#define __log_fatal(fmt, ...) \
    pr_emerg("%s.%s: " fmt, THIS_MODULE->name, __func__, ##__VA_ARGS__)
#define __log_error(fmt, ...) \
    pr_err  ("%s.%s: " fmt, THIS_MODULE->name, __func__, ##__VA_ARGS__)
#define __log_warn(fmt, ...)  \
    pr_warn ("%s.%s: " fmt, THIS_MODULE->name, __func__, ##__VA_ARGS__)
#define __log_info(fmt, ...)  \
    pr_info ("%s.%s: " fmt, THIS_MODULE->name, __func__, ##__VA_ARGS__)

#define __log_info_ratelimited(fmt, ...)  \
    pr_info_ratelimited("%s.%s: " fmt,    \
            THIS_MODULE->name, __func__, ##__VA_ARGS__)

#else

#define __log_fatal(fmt, ...) do {} while (0)
#define __log_error(fmt, ...) do {} while (0)
#define __log_warn(fmt, ...)  do {} while (0)
#define __log_info(fmt, ...)  do {} while (0)

#define __log_info_ratelimited(fmt, ...)  do {} while (0)

#endif

#ifdef DEBUG
#include <linux/slab.h>
void *os_kmalloc(size_t size, gfp_t flags);
void *os_kzalloc(size_t size, gfp_t flags);
void os_kfree(const void *p);
void __kmem_alloc_sanity(void);
#else
#define os_kmalloc kmalloc
#define os_kzalloc kzalloc
#define os_kfree kfree
#define __kmem_alloc_sanity() do {} while (0)
#endif

#endif /* SYSMON_DEBUG_H */
