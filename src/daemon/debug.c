#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "debug.h"

#ifdef DEBUG

FILE *__debug_fp;
int __debug_log_level = LOG_MAXIMUM;


static void vlog(const char *funcname, int line, const char *fmt, va_list va)
{
    char buffer[2048] = "\0";
    int len;
    time_t t;
    struct tm tm;

    time(&t);
    localtime_r(&t, &tm);
    len = strftime(buffer, sizeof(buffer), "%c: ", &tm);
    len += snprintf(&buffer[len], sizeof(buffer) - len,
                    "[%d %s] ", line, funcname);
    len += vsnprintf(&buffer[len], sizeof(buffer) - len, fmt, va);
    if (__debug_fp) {
        fprintf(__debug_fp, "%s", buffer);
        fflush(__debug_fp);
    } else {
        fprintf(stderr, "%s", buffer);
        fflush(stderr);
    }
}


void do_log(const char *funcname, int line, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vlog(funcname, line, fmt, va);
    va_end(va);
}

#endif
