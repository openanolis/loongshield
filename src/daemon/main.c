#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "debug.h"

/* lualibs.c */
extern void lualibs_openall(lua_State *L);

/* ramfs.c */
extern int ramfs_vfsinit(lua_State *L, const char *pathname, int argc,
                         const char *const argv[], const char *const envp[]);


static int pmain(lua_State *L)
{
    int argc = (int)lua_tointeger(L, 1);
    const char *const *argv = lua_touserdata(L, 2);
    const char *const *envp = lua_touserdata(L, 3);
    int err;

    luaL_openlibs(L);

    /* open builtin libraries */
    lualibs_openall(L);

    lua_gc(L, LUA_GCRESTART, 0);

    /* create rootfs and execute '/init.lua' */
    err = ramfs_vfsinit(L, "/init", argc, argv, envp);
    if (err < 0) {
        __log_error("err = %d, top = %d\n", err, lua_gettop(L));
        lua_pushinteger(L, EXIT_FAILURE);
    } else if (!lua_isnumber(L, -1)) {
        lua_pushinteger(L, lua_toboolean(L, -1) ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    return 1;
}

static int panic(lua_State *L)
{
    (void)L;  /* to avoid warnings */
    fprintf(stderr, "PANIC: unprotected error in call to Lua API (%s)\n",
            lua_tostring(L, -1));
    fflush(stderr);
    return 0;
}

int main(int argc, char *argv[], char *envp[])
{
    lua_State *L;
    int rc = EXIT_FAILURE;
    int status;

    __log_init(LOG_MAXIMUM, NULL);

    L = luaL_newstate();
    if (L == NULL) {
        __log_error("luaL_newstate(): No enough memory\n");
        __log_uninit();
        return EXIT_FAILURE;
    }

    lua_atpanic(L, panic);
    lua_gc(L, LUA_GCSTOP, 0);

    lua_pushcfunction(L, pmain);
    lua_pushinteger(L, argc);
    lua_pushlightuserdata(L, argv);
    lua_pushlightuserdata(L, envp);
    status = lua_pcall(L, 3, 1, 0);
    if (status != 0) {
        const char *msg = lua_tostring(L, -1);
        fprintf(stderr, "%s\n", msg);
        lua_pop(L, 1);
    } else if (lua_isnumber(L, -1)) {
        rc = (int)lua_tointeger(L, -1);
    } else if (lua_toboolean(L, -1)) {
        rc = EXIT_SUCCESS;
    } else {
        rc = EXIT_FAILURE;
    }

    lua_close(L);

    __log_uninit();

    return rc;
}
