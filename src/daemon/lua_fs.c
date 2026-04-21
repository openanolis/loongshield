#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include <lua.h>
#include <lauxlib.h>
#include "luauxlib.h"

#define META_STAT "meta_fs_stat"
#define tostatp(L, idx) (struct stat *)luaL_checkudata(L, idx, META_STAT)

static int stat_gc(lua_State *L) {
    return 0;
}

#define STAT_DEF_INTEGER(name, field) \
    static int stat_ ## name(lua_State *L) { \
        struct stat *sb = tostatp(L, 1); \
        lua_pushinteger(L, (lua_Integer)sb->field); \
        return 1; \
    }

STAT_DEF_INTEGER(uid,  st_uid)
STAT_DEF_INTEGER(gid,  st_gid)
STAT_DEF_INTEGER(size, st_size)

static int stat_mode(lua_State *L) {
    struct stat *sb = tostatp(L, 1);
    lua_pushinteger(L, (lua_Integer)(sb->st_mode & 07777));
    return 1;
}

static const luaL_Reg stat_meth[] = {
    { "__gc", stat_gc },
    { "uid",  stat_uid },
    { "gid",  stat_gid },
    { "mode", stat_mode },
    { "size", stat_size },
    { NULL, NULL }
};

static int L_stat(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    struct stat *sb = (struct stat *)lua_newuserdata(L, sizeof(*sb));

    if (stat(path, sb) == -1) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    luaL_getmetatable(L, META_STAT);
    lua_setmetatable(L, -2);
    return 1;
}

static int L_get_uid(lua_State *L) {
    const char *username = luaL_checkstring(L, 1);
    struct passwd *pws = getpwnam(username);
    if (pws != NULL) {
         lua_pushinteger(L, pws->pw_uid);
         return 1;
    }
    return 0;
}

static int L_get_gid(lua_State *L) {
    const char *groupname = luaL_checkstring(L, 1);
    struct group *grp = getgrnam(groupname);
    if (grp != NULL) {
        lua_pushinteger(L, grp->gr_gid);
        return 1;
    }
    return 0;
}


static int L_readfile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    FILE *fp = fopen(path, "r");

    if (!fp) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    size_t n;
    do {
        char *p = luaL_prepbuffer(&b);
        n = fread(p, 1, LUAL_BUFFERSIZE, fp);
        luaL_addsize(&b, n);
    } while (n > 0);

    fclose(fp);

    luaL_pushresult(&b);
    return 1;
}

static int L_chmod(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    mode_t mode = (mode_t)luaL_checkinteger(L, 2);

    if (chmod(path, mode) == -1) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int L_chown(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    uid_t uid = (uid_t)luaL_checkinteger(L, 2);
    gid_t gid = (gid_t)luaL_checkinteger(L, 3);

    if (chown(path, uid, gid) == -1) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static const luaL_Reg fs_lib[] = {
    { "stat",       L_stat      },
    { "get_uid",    L_get_uid   },
    { "get_gid",    L_get_gid   },
    { "readfile",   L_readfile  },
    { "chmod",      L_chmod     },
    { "chown",      L_chown     },
    { NULL, NULL }
};

LUALIB_API int luaopen_fs(lua_State *L) {
    luaL_newlib(L, fs_lib);
    createmeta(L, META_STAT, stat_meth);
    return 1;
}
