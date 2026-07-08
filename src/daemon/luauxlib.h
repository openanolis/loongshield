#ifndef LUAUXLIB_H
#define LUAUXLIB_H

#include <lua.h>
#include <lauxlib.h>

#define DEFINE_LUA_UDATA_PTR(name, type, metatable) \
    static inline type *to##name##p(lua_State *L, int idx) { \
        return (type *)luaL_checkudata(L, idx, metatable); \
    }

#define DEFINE_LUA_UDATA(name, type, metatable) \
    DEFINE_LUA_UDATA_PTR(name, type, metatable) \
    static inline type to##name(lua_State *L, int idx) { \
        return *to##name##p(L, idx); \
    }

struct cflag_opt {
    const char *name;
    unsigned int flag;
};

unsigned int
tocflags(lua_State *L, int idx, const struct cflag_opt *opts, unsigned int d);

const char *
fromcflags(const struct cflag_opt *opts, unsigned int flag, const char *d);


void **newcptr(lua_State *L, const char *metatable);
void createmeta(lua_State *L, const char *tname, const luaL_Reg *meth);

#endif /* ! LUAUXLIB_H */
