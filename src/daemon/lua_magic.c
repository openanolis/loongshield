#include <magic.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#ifndef NAME_MAGIC
#define NAME_MAGIC      "magic"
#endif

#define METH_MAGICNAME  "meth_magic"

struct magic_ctx {
    magic_t cookie;
};

static int l_magic_open(lua_State *L)
{
    int flags = luaL_checkint(L, 1);
    magic_t cookie;
    struct magic_ctx *ctx;

    cookie = magic_open(flags);
    if (cookie) {
        ctx = (struct magic_ctx *)lua_newuserdata(L, sizeof(*ctx));
        ctx->cookie = cookie;
        luaL_getmetatable(L, METH_MAGICNAME);
        lua_setmetatable(L, -2);
    } else {
        lua_pushnil(L);
    }

    return 1;
}

static struct magic_ctx *tomagic(lua_State *L, int idx)
{
    struct magic_ctx *ctx;
    ctx = (struct magic_ctx *)luaL_checkudata(L, idx, METH_MAGICNAME);
    luaL_argcheck(L, ctx != NULL, idx, "magic expected");
    return ctx;
}

static const luaL_Reg magiclib[] = {
    { "open",    l_magic_open    },
    { "version", l_magic_version },
    { NULL, NULL }
};

static const luaL_Reg magic_meth[] = {
    { "close",      l_magic_close       },
    { "error",      l_magic_error       },
    { "errno",      l_magic_errno       },
    { "descriptor", l_magic_descriptor  },
    { "file",       l_magic_file        },
    { "buffer",     l_magic_buffer      },
    { "getflags",   l_magic_getflags    },
    { "setflags",   l_magic_setflags    },
    { "check",      l_magic_check       },
    { "compile",    l_magic_compile     },
    { "list",       l_magic_list        },
    { "load",       l_magic_load        },
    { "loadbuffers", l_magic_loadbuffers },
    { "getparam",   l_magic_getparam    },
    { "setparam",   l_magic_setparam    },
    { "__gc",       l_magic_close       },
    { NULL, NULL }
};
