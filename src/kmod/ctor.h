#ifndef SYSMON_CTOR_H
#define SYSMON_CTOR_H

typedef void (*ctor_fn_t)(void);
typedef void (*dtor_fn_t)(void);

#define __initcall(fn)                      \
    static ctor_fn_t __init_ ## fn __used   \
    __attribute__((section(".ctor"))) = fn;
#define __exitcall(fn)                      \
    static dtor_fn_t __exit_ ## fn __used   \
    __attribute__((section(".dtor"))) = fn;

void ctor_init(void);
void dtor_exit(void);

#endif /* SYSMON_CTOR_H */
