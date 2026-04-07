#include "debug.h"
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/signal.h>
#include <linux/binfmts.h>
#include "filter.h"


/* alloc */

/* void wake_up_new_task(struct task_struct *p) */

FILTER_DEFINE1(wake_up_new_task, int/*void*/, struct task_struct *, p)
{
    return REAL(wake_up_new_task, p);
}


/* kill */

FILTER_DEFINE4(security_task_kill, int,
        struct task_struct *, task, struct siginfo *, info,
        int, sig, u32, secid)
{
    int ret;

    ret = REAL(security_task_kill, task, info, sig, secid);
    if (ret < 0)
        return ret;

    return ret;
}


/* ptrace */

FILTER_DEFINE4(ptrace_attach, int,
        struct task_struct *, child, long, request,
        unsigned long, addr, unsigned long, flags)
{
    return REAL(ptrace_attach, child, request, addr, flags);
}
