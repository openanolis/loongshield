#ifndef SYSMON_FILTER_H
#define SYSMON_FILTER_H

#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#undef LIST_HEAD
#include "queue.h"
#include "ctor.h"

#if !defined(CONFIG_X86) || !defined(CONFIG_X86_64)
#error "Unsupported platfrom! x86 or x86_64 is required"
#endif

struct filter {
    const char *fname;
    void *filter;
    void *real;
    TAILQ_ENTRY(filter) list;
    atomic_t watchdog;
    unsigned int flags;
    void *address;
    struct ftrace_ops ops;
    int error;
#ifdef FILTER_PROFILE
    atomic_t count;
    atomic64_t time;        /* ns */
    u64 maxtime;
    atomic64_t time_real;
    u64 maxtime_real;
#endif
    /* TODO:
    void *pre_filter;
    void *post_filter;
    */
};

int filter_set_status(int enable);
void filter_lasttime_update(void);
int filter_disabled(void);
void filter_register(struct filter *flt);

#ifdef FILTER_PROFILE
#define START_PROFILE(name)                                           \
    do {                                                              \
        ktime_t __start = ktime_get();                                \
        u64 __delta;                                                  \
        atomic_inc(&__flt_ ## name.count);

#define END_PROFILE(name)                                             \
        __delta = ktime_to_ns(ktime_get()) - ktime_to_ns(__start);    \
        /* TODO: atomic compare set */                                \
        if (__flt_ ## name.maxtime < __delta)                         \
            __flt_ ## name.maxtime = __delta;                         \
        atomic64_add(__delta, &__flt_ ## name.time);                  \
    } while (0)

#define REAL(name, ...)                                               \
    ({                                                                \
        typeof(__retype_ ## name) ___r;                               \
        ktime_t __start = ktime_get();                                \
        u64 __delta;                                                  \
        ___r = ((__fptr_ ## name)(__flt_ ## name.real))(__VA_ARGS__); \
        __delta = ktime_to_ns(ktime_get()) - ktime_to_ns(__start);    \
        if (__flt_ ## name.maxtime_real < __delta)                    \
            __flt_ ## name.maxtime_real = __delta;                    \
        atomic64_add(__delta, &__flt_ ## name.time_real);             \
        ___r;                                                         \
    })
#else
#define START_PROFILE(name)
#define END_PROFILE(name)

#define REAL(name, ...) ((__fptr_ ## name)(__flt_ ## name.real))(__VA_ARGS__)
#endif

#define FILTER_FLAGS(name, x)                   \
static void __set_filter_flags_ ## name(void) { \
    __flt_ ## name.flags |= (x);                \
}                                               \
__initcall(__set_filter_flags_ ## name);

#define FILTER_DEFINEx(x, name, type, ...)                              \
static type __wrapfilter_ ## name(__MAP(x, __SC_DECL, __VA_ARGS__));    \
static struct filter __flt_ ## name = {                                 \
    .fname = #name,                                                     \
    .filter = __wrapfilter_ ## name,                                    \
    .watchdog = ATOMIC_INIT(0),                                         \
};                                                                      \
static void __register_flt_ ## name(void) {                             \
    filter_register(&__flt_ ## name);                                   \
}                                                                       \
__initcall(__register_flt_ ## name);                                    \
typedef type (*__fptr_ ## name)(__MAP(x, __SC_DECL, __VA_ARGS__));      \
typedef type __retype_ ## name;                                         \
static inline type __filter_ ## name(__MAP(x, __SC_DECL, __VA_ARGS__)); \
static type __wrapfilter_ ## name(__MAP(x, __SC_DECL, __VA_ARGS__))     \
{                                                                       \
    type ret;                                                           \
    atomic_inc(&__flt_ ## name.watchdog);                               \
    START_PROFILE(name);                                                \
    if (filter_disabled()) {                                            \
        ret = REAL(name, __MAP(x, __SC_ARGS, __VA_ARGS__));             \
    } else {                                                            \
        ret = __filter_ ## name(__MAP(x, __SC_ARGS, __VA_ARGS__));      \
    }                                                                   \
    END_PROFILE(name);                                                  \
    atomic_dec(&__flt_ ## name.watchdog);                               \
    return ret;                                                         \
}                                                                       \
static inline type __filter_ ## name(__MAP(x, __SC_DECL, __VA_ARGS__))

#define FILTER_DEFINE0(name, t, ...) FILTER_DEFINE1(name, t, void, )
#define FILTER_DEFINE1(name, t, ...) FILTER_DEFINEx(1, name, t, __VA_ARGS__)
#define FILTER_DEFINE2(name, t, ...) FILTER_DEFINEx(2, name, t, __VA_ARGS__)
#define FILTER_DEFINE3(name, t, ...) FILTER_DEFINEx(3, name, t, __VA_ARGS__)
#define FILTER_DEFINE4(name, t, ...) FILTER_DEFINEx(4, name, t, __VA_ARGS__)
#define FILTER_DEFINE5(name, t, ...) FILTER_DEFINEx(5, name, t, __VA_ARGS__)
#define FILTER_DEFINE6(name, t, ...) FILTER_DEFINEx(6, name, t, __VA_ARGS__)
#define FILTER_DEFINE7(name, t, ...) FILTER_DEFINEx(7, name, t, __VA_ARGS__)
#define FILTER_DEFINE8(name, t, ...) FILTER_DEFINEx(8, name, t, __VA_ARGS__)

#ifndef __MAP7
#define __MAP7(m,t,a,...) m(t,a), __MAP6(m,__VA_ARGS__)
#define __MAP8(m,t,a,...) m(t,a), __MAP7(m,__VA_ARGS__)
#endif


#define PTREGS_NEED_REAL    1

int filter_hook(void);
int filter_unhook(void);

#endif /* SYSMON_FILTER_H */
