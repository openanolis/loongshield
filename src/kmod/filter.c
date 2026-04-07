#include "debug.h"
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/stop_machine.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/seq_file.h>
#include <linux/ftrace.h>
#include <net/netlink.h>
#include <asm/asm-offsets.h>
#include "securityfs.h"
#include "filter.h"

static int switch_on = 1;
static s64 lasttime;        /* ms */

static TAILQ_HEAD(, filter) flts = TAILQ_HEAD_INITIALIZER(flts);

int filter_set_status(int enable)
{
    int ret = switch_on;
    switch_on = !!enable;
    return ret;
}

void filter_lasttime_update(void)
{
    lasttime = ktime_to_ms(ktime_get());
}

static int filter_timeout(void)
{
    /* XXX: timeout: 30 s */
    return lasttime && ktime_to_ms(ktime_get()) - lasttime > 30 * 1000;
}

int filter_disabled(void)
{
    return !switch_on || filter_timeout();
}

void filter_register(struct filter *flt)
{
    __log_info("filter_register: %s\n", flt->fname);
    TAILQ_INSERT_TAIL(&flts, flt, list);
}

#ifdef FILTER_PROFILE
static int profile_show(struct seq_file *m, void *v)
{
    struct filter *flt;

    seq_printf(m, "runtime for filter (ns)\n");
    seq_printf(m, "%-28s %8s %15s %10s %15s\n",
            "name", "count", "total", "average", "real");

    TAILQ_FOREACH(flt, &flts, list) {
        if (flt->error >= 0) {
            int n = atomic_read(&flt->count);
            u64 total = atomic64_read(&flt->time);
            u64 real = atomic64_read(&flt->time_real);
            seq_printf(m, "%-28s %8d %15llu %10llu %15llu\n",
                    flt->fname, n, total - real,
                    n ? (total - real) / n : 0, real);
        } else {
            seq_printf(m, "%-28s error = %d\n", flt->fname, flt->error);
        }
    }
    return 0;
}
SYSFS_ENT_DEFINE(profile, profile_show);
#endif


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
#ifdef CONFIG_KPROBES

static int handler_pre(struct kprobe *kp, struct pt_regs *regs)
{
    return 0;
}

static void *sym_lookup_by_kprobe(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name,
        .pre_handler = handler_pre,
    };
    int err;

    err = register_kprobe(&kp);
    if (err)
        return NULL;
    unregister_kprobe(&kp);
    return kp.addr;
}

#else

static void *sym_lookup_by_kprobe(const char *name)
{
    return NULL;
}

#endif
#endif

static void *sym_lookup(const char *name)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    static kallsyms_lookup_name_t kallsyms_lookup_name;
    if (kallsyms_lookup_name == NULL)
        kallsyms_lookup_name = sym_lookup_by_kprobe("kallsyms_lookup_name");
    if (kallsyms_lookup_name == NULL)
        return NULL;
#endif
    return (void *)kallsyms_lookup_name(name);
}

/* TODO: 3.10 NO within_module */
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 11, 0))
static inline bool within_module(unsigned long addr, const struct module *mod)
{
    return within_module_init(addr, mod) || within_module_core(addr, mod);
}
#endif

static void notrace filter_ftrace_thunk(unsigned long ip,
        unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct filter *flt = container_of(ops, struct filter, ops);
    if (!within_module(parent_ip, THIS_MODULE)) {
        /*
        __log_info_ratelimited("regs->ip update: %s\n", flt->fname);
        */
        regs->ip = (unsigned long)flt->filter;
    }
}

static int filter_set_ftrace(struct filter *flt)
{
    void *addr;
    int err;

    addr = (void *)sym_lookup(flt->fname);
    if (addr == NULL)
        return -ENOENT;

    flt->address = addr;
    flt->real = addr + MCOUNT_INSN_SIZE;
    barrier();

    flt->ops.func = filter_ftrace_thunk;
    flt->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                   | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&flt->ops, (unsigned long)addr, 0, 0);
    if (err)
        return err;

    err = register_ftrace_function(&flt->ops);
    if (err) {
        ftrace_set_filter_ip(&flt->ops, (unsigned long)addr, 1, 0);
        return err;
    }

    return 0;
}

static int filter_remove_ftrace(struct filter *flt)
{
    int err;

    err = unregister_ftrace_function(&flt->ops);
    if (err)
        return err;

    err = ftrace_set_filter_ip(&flt->ops, (unsigned long)flt->address, 1, 0);
    if (err)
        return err;

    return 0;
}

int filter_hook(void)
{
    struct filter *flt;
    int n = 0;

    TAILQ_FOREACH(flt, &flts, list) {
        flt->error = filter_set_ftrace(flt);
        if (!flt->error)
            n += 1;
        else
            __log_error("set_ftrace, %s, err = %d", flt->fname, flt->error);
    }

    if (flt && flt->error < 0) {
        /* TODO: rollback */
    }

    return n;
}

static int filter_restore_sanity(void *userdata)
{
    struct filter *flt;
    int inuse = 0;
    TAILQ_FOREACH(flt, &flts, list) {
        inuse += atomic_read(&flt->watchdog);
    }
    return inuse;
}

static int filter_sanity(void)
{
    unsigned int elapse = 0;

    while (filter_restore_sanity(NULL)) {
        msleep_interruptible(10);   /* 10 ms */
        elapse += 10;
    }

    if (elapse > 100)
        __log_warn("elapse = %d ms\n", elapse);

    /* TODO: ensure once schedule */
    msleep_interruptible(10);
    return 0;
}

int filter_unhook(void)
{
    struct filter *flt;
    int n = 0;

    TAILQ_FOREACH(flt, &flts, list) {
        int err;

        if (flt->real == NULL || flt->error < 0)
            continue;

        err = filter_remove_ftrace(flt);
        if (err) {
            __log_error("remove_ftrace, %s, err = %d", flt->fname, err);
            /* TODO */
        }
        n += 1;
        __log_info("watchdog = %d, %s\n",
                atomic_read(&flt->watchdog), flt->fname);
    }

    return filter_sanity();
}
