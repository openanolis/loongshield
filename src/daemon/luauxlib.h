#ifndef LUAUXLIB_H
#define LUAUXLIB_H

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
