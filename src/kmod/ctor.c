#include "ctor.h"

extern ctor_fn_t ctor_start[], ctor_end[];
extern dtor_fn_t dtor_start[], dtor_end[];

void ctor_init(void)
{
    ctor_fn_t *start = ctor_start;
    while (start < ctor_end) {
        if (*start)
            (*start)();
        ++start;
    }
}

void dtor_exit(void)
{
    dtor_fn_t *start = dtor_start;
    while (start < dtor_end) {
        if (*start)
            (*start)();
        ++start;
    }
}
