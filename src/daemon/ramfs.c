#include <stdio.h>
#include <errno.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "debug.h"

static void stack_dump(lua_State *L)
{
    int top = lua_gettop(L);
    int i;

    __log_info("-------- stack dump --------\n");
    for (i = 1; i <= top; i++) {
        int t = lua_type(L, i);
        const char *tn = lua_typename(L, t);
        __log_info("    %2d [%s]:\n", i, tn);
    }
    __log_info("-------- stack dump --------\n");
}

/* borrowed from lua.c */
static int traceback(lua_State *L)
{
    if (!lua_isstring(L, 1))  /* 'message' not a string? */
        return 1;  /* keep it intact */
    lua_getfield(L, LUA_GLOBALSINDEX, "debug");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return 1;
    }
    lua_getfield(L, -1, "traceback");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 2);
        return 1;
    }
    lua_pushvalue(L, 1);  /* pass error message */
    lua_pushinteger(L, 2);  /* skip this function and traceback */
    lua_call(L, 2, 1);  /* call debug.traceback */
    return 1;
}

int ramfs_vfsinit(lua_State *L, const char *pathname, int argc,
                  const char *const argv[], const char *const envp[])
{
    static const char ramfs_luac[] = {
    /* NO compression */
#include "bin_ramfs_luac.h"
    };
    static const char initrd_tar[] = {
#include "bin_initrd_tar.h"
    };
    int status = LUA_ERRERR;
    int err = -EDOM;
    int i;

    do {
        /*
         * local vfs = require("ramfs")
         * vfs.init(initrd, pathname, argv, envp)
         */
        err = -ENOENT;
        status = luaL_loadbuffer(L, ramfs_luac, sizeof(ramfs_luac), NULL);
        if (status != 0)
            break;

        /* local vfs = require("ramfs") */
        err = -ENOEXEC;
        lua_pushstring(L, "ramfs");
        status = lua_pcall(L, 1, 1, 0);
        if (status != 0 || !lua_istable(L, -1))
            break;

        /* -- save to package.loaded table */
        lua_getfield(L, LUA_REGISTRYINDEX, "_LOADED");
        lua_pushvalue(L, -2);
        lua_setfield(L, -2, "ramfs");   /* _LOADED.ramfs = returned value */
        lua_pop(L, 1);

        /* ... = vfs.init(initrd, pathname, argv, envp) */
        err = -EDOM;
        lua_pushcfunction(L, traceback);
        lua_getfield(L, -2, "init");
        if (!lua_isfunction(L, -1))
            break;
        lua_pushlstring(L, initrd_tar, sizeof(initrd_tar));
        lua_pushstring(L, pathname);

        /* create argv and envp table */
        lua_createtable(L, argc, 0);
        for (i = 0; i < argc; i++) {
            lua_pushstring(L, argv[i]);
            lua_rawseti(L, -2, i + 1);
        }
        lua_newtable(L);
        for (i = 0; envp[i] != NULL; i++) {
            lua_pushstring(L, envp[i]);
            lua_rawseti(L, -2, i + 1);
        }

        err = -ENOEXEC;
        /* stack: [ramfs, traceback, init, initrd, pathname, argv, envp] */
        status = lua_pcall(L, 4, 1/*LUA_MULTRET*/, -6);
        if (status != 0) {
            const char *msg;

            if (!lua_isnil(L, -1) && (msg = lua_tostring(L, -1))) {
                __log_error("%s\n", msg);
            } else {
                __log_error("ramfs_vfsinit: status = %d, top = %d, rc = %s\n",
                            status, lua_gettop(L),
                            lua_typename(L, lua_type(L, -1)));
            }
            break;
        }

        err = 0;
    } while (0);

    /* TODO: clear stack */
    return err;
}
