
if (WIN32)
    # TODO
else ()
    set(SRCS_LIB_LIBUV
        libuv/src/unix/async.c
        libuv/src/unix/core.c
        libuv/src/unix/dl.c
        libuv/src/unix/fs.c
        libuv/src/unix/getaddrinfo.c
        libuv/src/unix/getnameinfo.c
        libuv/src/unix/loop-watcher.c
        libuv/src/unix/loop.c
        libuv/src/unix/pipe.c
        libuv/src/unix/poll.c
        libuv/src/unix/process.c
        libuv/src/unix/proctitle.c
        libuv/src/unix/random-devurandom.c
        libuv/src/unix/signal.c
        libuv/src/unix/stream.c
        libuv/src/unix/tcp.c
        libuv/src/unix/thread.c
        libuv/src/unix/tty.c
        libuv/src/unix/udp.c
        )

    if (APPLE)
        set(SRCS_LIB_LIBUV
            ${SRCS_LIB_LIBUV}
            libuv/src/unix/bsd-ifaddrs.c
            libuv/src/unix/darwin-proctitle.c
            libuv/src/unix/darwin.c
            libuv/src/unix/fsevents.c
            libuv/src/unix/kqueue.c
            libuv/src/unix/random-getentropy.c
            )
    elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        set(SRCS_LIB_LIBUV
            ${SRCS_LIB_LIBUV}
            libuv/src/unix/epoll.c
            libuv/src/unix/linux-core.c
            libuv/src/unix/linux-inotify.c
            libuv/src/unix/linux-syscalls.c
            libuv/src/unix/procfs-exepath.c
            libuv/src/unix/random-getrandom.c
            libuv/src/unix/random-sysctl-linux.c
            )
    else ()
        # TODO
    endif ()
endif ()

set(SRCS_LIB_LIBUV
    ${SRCS_LIB_LIBUV}
    libuv/src/fs-poll.c
    libuv/src/idna.c
    libuv/src/inet.c
    libuv/src/random.c
    libuv/src/strscpy.c
    libuv/src/strtok.c
    libuv/src/threadpool.c
    libuv/src/timer.c
    libuv/src/uv-common.c
    libuv/src/uv-data-getter-setters.c
    libuv/src/version.c
    )

source_group("libuv" FILES ${SRCS_LIB_LIBUV})


add_library(libuv STATIC ${SRCS_LIB_LIBUV})
target_include_directories(libuv BEFORE
    PRIVATE "libuv/src"
    PRIVATE "libuv/include"
    )

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set_target_properties(libuv
        PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE"
        )
endif ()

set_target_properties(libuv
    PROPERTIES
    FOLDER "deps"
    )
