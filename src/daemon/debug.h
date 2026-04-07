#ifndef LIB_DEBUG_H
#define LIB_DEBUG_H

#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef enum {
    LOG_NOTHING,
    LOG_FATAL,
    LOG_ALERT,
    LOG_CRIT,
    LOG_ERROR,
    LOG_WARN,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG,
    LOG_TRACE,
    LOG_TEST,
    LOG_MAXIMUM
} log_level;

#ifdef DEBUG

extern FILE *__debug_fp;
extern int __debug_log_level;

void do_log(const char *funcname, int line, const char *fmt, ...);


#define __dprint_init(level, file)              \
    do {                                        \
        __debug_log_level = (level);            \
        if (file)                               \
            __debug_fp = fopen(file, "a");      \
    } while (0)

#define __dprint_uninit()                       \
    do {                                        \
        __debug_log_level = LOG_NOTHING;        \
        if (__debug_fp)                         \
            fclose(__debug_fp);                 \
    } while (0)


#define __dprintf(level, fmt, ...)                                  \
    do {                                                            \
        if ((level) < __debug_log_level) {                          \
            do_log(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__);     \
        }                                                           \
    } while (0)

#else

#define __dprint_init(level, file)  do {} while (0)
#define __dprint_uninit()           do {} while (0)
#define __dprintf(level, fmt, ...)  do {} while (0)

#endif

#define __log_init(level, file)     __dprint_init(level, file)
#define __log_uninit()              __dprint_uninit()
#define __log_fatal(fmt, ...) __dprintf(LOG_FATAL, "fatal " fmt, ##__VA_ARGS__)
#define __log_error(fmt, ...) __dprintf(LOG_ERROR, "error " fmt, ##__VA_ARGS__)
#define __log_warn(fmt, ...)  __dprintf(LOG_WARN, "warn " fmt, ##__VA_ARGS__)
#define __log_info(fmt, ...)  __dprintf(LOG_INFO, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* ! LIB_DEBUG_H */
