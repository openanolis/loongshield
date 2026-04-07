#include "debug.h"
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/miscdevice.h>
#include <linux/compat.h>
#include <linux/seq_file.h>
#include <linux/profile.h>
#include "ctor.h"
#include "filter.h"
#include "securityfs.h"

#define DEV_MISC_NAME   BASENAME


static int version_show(struct seq_file *m, void *v)
{
    seq_printf(m, "%s kmod v1, built on %s %s, by GCC %s\n",
            BASENAME, __DATE__, __TIME__, __VERSION__);
    return 0;
}
SYSFS_ENT_DEFINE(version, version_show);

static int kmod_open(struct inode *inode, struct file *filp)
{
    __log_info("kmod_open: tgid = %d\n", current->tgid);
    return 0;
}

static int kmod_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static long kmod_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return 0;
}

#ifdef CONFIG_COMPAT
static long kmod_compat_ioctl(struct file *filp,
            unsigned int cmd, unsigned long arg)
{
    return 0;
}
#endif

static const struct file_operations kmod_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = kmod_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = kmod_compat_ioctl,
#endif
    .open = kmod_open,
    .release = kmod_release
};

static struct miscdevice miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = BASENAME,
    .nodename = DEV_MISC_NAME,
    .fops = &kmod_fops,
};

int kmain_init(void)
{
    int ret;

    ctor_init();

    ret = securityfs_init();
    if (ret < 0)
        goto err_ctor;

    ret = misc_register(&miscdev);
    if (ret)
        goto err_securityfs;

    ret = filter_hook();
    if (ret < 0)
        goto err_misc;

    return 0;

err_misc:
    misc_deregister(&miscdev);
err_securityfs:
    securityfs_exit();
err_ctor:
    dtor_exit();
    return ret;
}

void kmain_exit(void)
{
    filter_unhook();
    misc_deregister(&miscdev);
    securityfs_exit();
    dtor_exit();
    __kmem_alloc_sanity();
    __log_info("----------- leave kmod -----------\n");
}

MODULE_LICENSE("GPL");
module_init(kmain_init);
module_exit(kmain_exit);
