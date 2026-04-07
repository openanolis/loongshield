#ifndef LUA_H_OVERRIDE
#define LUA_H_OVERRIDE

#include "../luajit/luajit/src/lua.h"

/*
 * XXX: Overwrite the original macro
 * Consider luajit as lua v5.2,
 * in order to make lua-cjson pass the compilation smoothly
 */
#define LUA_VERSION_NUM 502

#endif
