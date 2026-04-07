loongshield_add_lua_library(
    NAME luaposix
    SOURCES
        luaposix/ext/posix/posix.c
    INCLUDE_DIRS
        "${CMAKE_CURRENT_SOURCE_DIR}/luaposix/ext/include"
    COMPILE_DEFINITIONS
        PACKAGE="luaposix"
        VERSION="luaposix"
        _XOPEN_SOURCE=700
        HAVE_NET_IF_H
        IFNAMSIZ=16
)
