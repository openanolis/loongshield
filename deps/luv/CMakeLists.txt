loongshield_add_lua_library(
    NAME luv
    SOURCES
        luv/src/luv.c
    INCLUDE_DIRS
        ${LIBUV_INCLUDE_DIR}
    LINK_LIBRARIES
        libuv
)
