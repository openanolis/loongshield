#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/xattr.h>

#include <lua.h>
#include <lauxlib.h>
#include "luauxlib.h"

#define META_XATTR_FILE "meta_xattr_file"

#define toxattrfilepath(L, idx) \
    (*(char **)luaL_checkudata((L), (idx), META_XATTR_FILE))

static int file_gc(lua_State *L) {
    char **path_ptr = (char **)luaL_checkudata(L, 1, META_XATTR_FILE);
    if (path_ptr && *path_ptr) {
        free(*path_ptr);
        *path_ptr = NULL;
    }
    return 0;
}

static int push_error(lua_State *L) {
    lua_pushnil(L);
    lua_pushstring(L, strerror(errno));
    return 2;
}

static int file_get(lua_State *L) {
    const char *path = toxattrfilepath(L, 1);
    const char *name = luaL_checkstring(L, 2);

    ssize_t size = getxattr(path, name, NULL, 0);
    if (size < 0) { return push_error(L); }
    if (size == 0) { lua_pushliteral(L, ""); return 1; }

    char *value = malloc(size);
    if (!value) { return luaL_error(L, "memory allocation failed"); }

    ssize_t read_size = getxattr(path, name, value, size);
    if (read_size < 0) {
        free(value);
        return push_error(L);
    }

    lua_pushlstring(L, value, read_size);
    free(value);
    return 1;
}

static int file_set(lua_State *L) {
    const char *path = toxattrfilepath(L, 1);
    const char *name = luaL_checkstring(L, 2);
    size_t value_len;
    const char *value = luaL_checklstring(L, 3, &value_len);
    int flags = luaL_optinteger(L, 4, 0);

    if (setxattr(path, name, value, value_len, flags) < 0) {
        return push_error(L);
    }
    lua_pushboolean(L, 1);
    return 1;
}

static int file_list(lua_State *L) {
    const char *path = toxattrfilepath(L, 1);

    ssize_t size = listxattr(path, NULL, 0);
    if (size < 0) { return push_error(L); }
    if (size == 0) { lua_newtable(L); return 1; }

    char *list = malloc(size);
    if (!list) { return luaL_error(L, "memory allocation failed"); }

    ssize_t read_size = listxattr(path, list, size);
    if (read_size < 0) {
        free(list);
        return push_error(L);
    }

    lua_newtable(L);

    char *p;
    int i = 1;
    for (p = list; p < list + read_size; p += strlen(p) + 1) {
        lua_pushstring(L, p);
        lua_rawseti(L, -2, i++);
    }

    free(list);
    return 1;
}

static int file_remove(lua_State *L) {
    const char *path = toxattrfilepath(L, 1);
    const char *name = luaL_checkstring(L, 2);

    if (removexattr(path, name) < 0) {
        return push_error(L);
    }
    lua_pushboolean(L, 1);
    return 1;
}

static const luaL_Reg xattr_meth[] = {
    { "__gc",   file_gc     },
    { "get",    file_get    },
    { "set",    file_set    },
    { "list",   file_list   },
    { "remove", file_remove },
    { NULL,     NULL }
};


static int L_new(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    char **path_ptr = (char **)newcptr(L, META_XATTR_FILE);
    *path_ptr = strdup(path);
    if (*path_ptr == NULL) {
        return luaL_error(L, "strdup failed: out of memory");
    }
    return 1;
}

static const luaL_Reg xattr_lib[] = {
    { "new", L_new },
    { NULL, NULL }
};

LUALIB_API int luaopen_xattr(lua_State *L) {
    luaL_newlib(L, xattr_lib);

    createmeta(L, META_XATTR_FILE, xattr_meth);

    lua_pushinteger(L, XATTR_CREATE);
    lua_setfield(L, -2, "CREATE");
    lua_pushinteger(L, XATTR_REPLACE);
    lua_setfield(L, -2, "REPLACE");

    return 1;
}
