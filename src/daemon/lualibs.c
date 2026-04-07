#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

int luaopen_lpeg(lua_State *L);
int luaopen_lfs(lua_State * L);
int luaopen_cjson_safe(lua_State *L);
int luaopen_lcurl_safe(lua_State *L);
LUALIB_API int luaopen_luv(lua_State *L);
LUALIB_API int luaopen_openssl(lua_State *L);
LUALIB_API int luaopen_kmod(lua_State *L);
LUALIB_API int luaopen_systemd(lua_State *L);
LUALIB_API int luaopen_archive(lua_State *L);
LUALIB_API int luaopen_audit(lua_State *L);
LUALIB_API int luaopen_mount(lua_State *L);
LUALIB_API int luaopen_lrpm(lua_State *L);
LUALIB_API int luaopen_dbus(lua_State *L);
LUALIB_API int luaopen_capability(lua_State *L);
LUALIB_API int luaopen_posix_unistd(lua_State *L);
LUALIB_API int luaopen_posix_glob(lua_State *L);
LUALIB_API int luaopen_posix_sys_utsname(lua_State *L);
LUALIB_API int luaopen_xattr(lua_State *L);
LUALIB_API int luaopen_fs(lua_State *L);
LUALIB_API int luaopen_yaml(lua_State *L);

static const luaL_Reg builtinlibs[] = {
    { "lpeg",              luaopen_lpeg              },
    { "lfs",               luaopen_lfs               },
    { "cjson.safe",        luaopen_cjson_safe        },
    { "lcurl.safe",        luaopen_lcurl_safe        },
    { "luv",               luaopen_luv               },
    { "openssl",           luaopen_openssl           },
    { "kmod",              luaopen_kmod              },
    { "systemd",           luaopen_systemd           },
    { "archive",           luaopen_archive           },
    { "audit",             luaopen_audit             },
    { "mount",             luaopen_mount             },
    { "lrpm",              luaopen_lrpm              },
    { "dbus",              luaopen_dbus              },
    { "capability",        luaopen_capability        },
    { "posix.unistd",      luaopen_posix_unistd      },
    { "posix.glob",        luaopen_posix_glob        },
    { "posix.sys.utsname", luaopen_posix_sys_utsname },
    { "xattr",             luaopen_xattr             },
    { "fs",                luaopen_fs                },
    { "yaml",              luaopen_yaml              },
    { NULL, NULL }
};


#if LUA_VERSION_NUM < 502

/*
** Stripped-down 'require': After checking "loaded" table, calls 'openf'
** to open a module, registers the result in 'package.loaded' table and,
** if 'glb' is true, also registers the result in the global table.
** Leaves resulting module on the top.
*/
static void luaL_requiref(lua_State *L, const char *modname,
                          lua_CFunction openf, int glb)
{
    luaL_findtable(L, LUA_REGISTRYINDEX, "_LOADED", 1);
    lua_getfield(L, -1, modname);  /* _LOADED[modname] */
    if (!lua_toboolean(L, -1)) {  /* package not already loaded? */
        lua_pop(L, 1);  /* remove field */
        lua_pushcfunction(L, openf);
        lua_pushstring(L, modname);  /* argument to open function */
        lua_call(L, 1, 1);  /* call 'openf' to open module */
        lua_pushvalue(L, -1);  /* make copy of module (call result) */
        lua_setfield(L, -3, modname);  /* _LOADED[modname] = module */
    }
    lua_remove(L, -2);  /* remove _LOADED table */
    if (glb) {
        lua_pushvalue(L, -1);  /* copy of module */
        lua_setglobal(L, modname);  /* _G[modname] = module */
    }
}

#endif


void lualibs_openall(lua_State *L)
{
    const luaL_Reg *lib;

    /* TODO: loaded if needed */
    for (lib = builtinlibs; lib->func; lib++) {
        luaL_requiref(L, lib->name, lib->func, 1/*TODO*/);
        lua_pop(L, 1);
    }
}
