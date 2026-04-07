#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <compat-5.3.h>

#include "luauxlib.h"


unsigned int
tocflags(lua_State *L, int idx, const struct cflag_opt *opts, unsigned int d)
{
    unsigned int flags = 0;
    const char *s;
    int k, i;

    switch (lua_type(L, idx)) {
    case LUA_TSTRING:
        s = lua_tostring(L, idx);
        for (i = 0; opts[i].name; i++) {
            if (strcasecmp(s, opts[i].name) != 0)
                continue;
            flags |= opts[i].flag;
            break;
        }
        break;

    case LUA_TTABLE:
        k = 1, lua_rawgeti(L, idx, k);
        for ( ; !lua_isnil(L, -1); lua_pop(L, 1), lua_rawgeti(L, idx, ++k)) {
            if (lua_type(L, -1) != LUA_TSTRING)
                continue;
            s = lua_tostring(L, -1);
            for (i = 0; opts[i].name; i++) {
                if (strcasecmp(s, opts[i].name) != 0)
                    continue;
                flags |= opts[i].flag;
                break;
            }
        }
        lua_pop(L, 1);
        break;

    case LUA_TNUMBER:
        flags |= (unsigned int)lua_tointeger(L, idx);
        break;

    case LUA_TBOOLEAN:
        if (lua_toboolean(L, idx))
            break;
        /* else fall through */
    case LUA_TNONE:
    case LUA_TNIL:
        flags = d;      /* default flags */
        break;
    }

    return flags;
}

const char *
fromcflags(const struct cflag_opt *opts, unsigned int flag, const char *d)
{
    int i;
    for (i = 0; opts[i].name; i++) {
        if (opts[i].flag == flag)
            return opts[i].name;
    }
    return d;
}

void **newcptr(lua_State *L, const char *metatable)
{
    void **p = (void **)lua_newuserdata(L, sizeof(void *));
    *p = NULL;
    luaL_getmetatable(L, metatable);
    lua_setmetatable(L, -2);
    return p;
}

void createmeta(lua_State *L, const char *tname, const luaL_Reg *meth)
{
    luaL_newmetatable(L, tname);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");     /* metatable.__index = metatable */
    luaL_register(L, NULL, meth);       /* equal: luaL_setfuncs(L, meth, 0) */
    lua_pop(L, 1);
}
