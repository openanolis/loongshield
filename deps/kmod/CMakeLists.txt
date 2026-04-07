set(SRCS_LIBKMOD
    kmod/shared/array.c
    kmod/shared/hash.c
    kmod/shared/scratchbuf.c
    kmod/shared/strbuf.c
    kmod/shared/util.c
    kmod/libkmod/libkmod-builtin.c
    kmod/libkmod/libkmod-config.c
    kmod/libkmod/libkmod-elf.c
    kmod/libkmod/libkmod-file.c
    kmod/libkmod/libkmod-index.c
    kmod/libkmod/libkmod-list.c
    kmod/libkmod/libkmod-module.c
    kmod/libkmod/libkmod-signature.c
    kmod/libkmod/libkmod.c
)

source_group("libkmod" FILES ${SRCS_LIBKMOD})

add_library(libkmod STATIC ${SRCS_LIBKMOD})
add_dependencies(libkmod libopenssl)

target_include_directories(libkmod PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/kmod"
)

# Fixed: Use target_compile_definitions instead of multiple COMPILE_FLAGS
# (Previous code had bug: multiple COMPILE_FLAGS assignments, only last took effect)
target_compile_definitions(libkmod PRIVATE
    ENABLE_LOGGING
    ENABLE_OPENSSL
    ENABLE_XZ
    ENABLE_ZLIB
    ENABLE_ZSTD
    HAVE_LINUX_MODULE_H
    SYSCONFDIR="/etc"
)

target_compile_options(libkmod PRIVATE
    -include config.h
)

target_link_libraries(libkmod PRIVATE zstd lzma z)

set_target_properties(libkmod PROPERTIES FOLDER "deps")
