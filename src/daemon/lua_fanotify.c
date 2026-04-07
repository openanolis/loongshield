#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <fcntl.h>
#include <sys/fanotify.h>

#ifndef NAME_FANOTIFY
#define NAME_FANOTIFY   "fanotify"
#endif

#define METH_FANOTIFYNAME   "meth_fanotify"

struct fanotify_ctx {
    int fd;
};

static int l_fanotify_init(lua_State *L)
{
    unsigned int flags = (unsigned int)luaL_checkint(L, 1);
    unsigned int event_flags = (unsigned int)luaL_checkint(L, 2);
    int fd;
    struct fanotify_ctx *ctx;

    fd = fanotify_init(flags, event_flags);
    if (fd == -1) {
        lua_pushnil(L);
        lua_pushinteger(L, errno);
        return 2;
    }

    ctx = (struct fanotify_ctx *)lua_newuserdata(L, sizeof(*ctx));
    ctx->fd = fd;
    luaL_getmetatable(L, METH_FANOTIFYNAME);
    lua_setmetatable(L, -2);
    return 1;
}

static struct fanotify_ctx *tofanotify(lua_State *L, int idx)
{
    struct fanotify_ctx *ctx;
    ctx = (struct fanotify_ctx *)luaL_checkudata(L, idx, METH_FANOTIFYNAME);
    luaL_argcheck(L, ctx != NULL, idx, "fanotify expected");
    return ctx;
}

static int l_fanotify_mark(lua_State *L)
{
    struct fanotify_ctx *ctx = tofanotify(L, 1);
    unsigned int flags = (unsigned int)luaL_checkint(L, 2);
    unsigned int mask = (unsigned int)luaL_checkint(L, 3);
    int dirfd = luaL_checkint(L, 4);
    const char *pathname = luaL_checkstring(L, 5);
    int err;

    err = fanotify_mark(ctx->fd, flags, mask, dirfd, pathname);
    if (err == -1) {
        lua_pushnil(L);
        lua_pushinteger(L, errno);
        return 2;
    }

    lua_settop(L, 1);
    return 1;
}

static int l_fanotify_close(lua_State *L)
{
    struct fanotify_ctx *ctx = tofanotify(L, 1);
    if (ctx->fd != -1) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    return 0;
}

static int l_fanotify_tostring(lua_State *L)
{
    struct fanotify_ctx *ctx = tofanotify(L, 1);
    lua_pushfstring(L, METH_FANOTIFYNAME " (fd = %d)", ctx->fd);
    return 1;
}

static const luaL_Reg fanotifylib[] = {
    { "init", l_fanotify_init },
    { NULL, NULL }
};

static const luaL_Reg fanotify_meth[] = {
    /*
    { "getfd", l_fanotify_getfd },
    */
    { "mark",  l_fanotify_mark  },
    /*
    { "read",  l_fanotify_read  },
    { "write", l_fanotify_write },
    */
    { "close", l_fanotify_close },
    { "__gc",  l_fanotify_close },
    { "__tostring", l_fanotify_tostring },
    { NULL, NULL }
};

#define CON_ENTRY(x)    { #x, x }

static struct fanotify_const {
    const char *name;
    unsigned int v;
} fanotify_consts[] = {
    CON_ENTRY(FAN_MARK_MOUNT),
    { NULL, 0 }
};

#undef CON_ENTRY

static void setconsts(lua_State *L)
{
    const struct fanotify_const *p;
    for (p = fanotify_consts; p->name; ++p) {
        lua_pushstring(L, p->name);
        lua_pushinteger(L, (lua_Integer)p->v);
        lua_settable(L, -3);
    }
}

static void createmeta(lua_State *L)
{
    luaL_newmetatable(L, METH_FANOTIFYNAME);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");     /* metatable.__index = metatable */
#if LUA_VERSION_NUM < 502
    luaL_register(L, NULL, fanotify_meth);
#else
    luaL_setfuncs(L, fanotify_meth, 0);
#endif
    lua_pop(L, 1);
}

LUALIB_API int luaopen_fanotify(lua_State *L)
{
#if LUA_VERSION_NUM < 502
    luaL_register(L, NAME_FANOTIFY, fanotifylib);
#else
    luaL_newlib(L, fanotifylib);
#endif
    createmeta(L);
    setconsts(L);
    return 1;
}
