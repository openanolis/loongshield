
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <compat-5.3.h>

#include "luauxlib.h"

#include <libmount/libmount.h>

#ifndef true
#define true    1
#define false   0
#endif

#define METH_MOUNT_MNT_FS           "meth_mount_mnt_fs"
#define METH_MOUNT_MNT_TABLE        "meth_mount_mnt_table"
#define METH_MOUNT_MNT_CONTEXT      "meth_mount_mnt_context"
#define METH_MOUNT_MNT_CACHE        "meth_mount_mnt_cache"
#define METH_MOUNT_MNT_ITER         "meth_mount_mnt_iter"

#define newmntfs(L)      (struct libmnt_fs **)newcptr((L), METH_MOUNT_MNT_FS)
#define newmnttable(L)   (struct libmnt_table **)newcptr((L), METH_MOUNT_MNT_TABLE)
#define newmntcontext(L) (struct libmnt_context **)newcptr((L), METH_MOUNT_MNT_CONTEXT)
#define newmntcache(L)   (struct libmnt_cache **)newcptr((L), METH_MOUNT_MNT_CACHE)
#define newmntiter(L)    (struct libmnt_iter **)newcptr((L), METH_MOUNT_MNT_ITER)

#define tomntfsp(L, idx)        \
    (struct libmnt_fs **)luaL_checkudata((L), (idx), METH_MOUNT_MNT_FS)
#define tomnttablep(L, idx)     \
    (struct libmnt_table **)luaL_checkudata((L), (idx), METH_MOUNT_MNT_TABLE)
#define tomntcontextp(L, idx)   \
    (struct libmnt_context **)luaL_checkudata((L), (idx), METH_MOUNT_MNT_CONTEXT)
#define tomntcachep(L, idx)     \
    (struct libmnt_cache **)luaL_checkudata((L), (idx), METH_MOUNT_MNT_CACHE)
#define tomntiterp(L, idx)      \
    (struct libmnt_iter **)luaL_checkudata((L), (idx), METH_MOUNT_MNT_ITER)

#define tomntfs(L, idx)         (*tomntfsp(L, idx))
#define tomnttable(L, idx)      (*tomnttablep(L, idx))
#define tomntcontext(L, idx)    (*tomntcontextp(L, idx))
#define tomntcache(L, idx)      (*tomntcachep(L, idx))
#define tomntiter(L, idx)       (*tomntiterp(L, idx))


static int mnt_result(lua_State *L, int err)
{
    if (err == 0) {
        lua_pushboolean(L, 1);
        return 1;
    } else if (err > 0) {
        lua_pushinteger(L, err);
        return 1;
    } else {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
}


#define MNT_UDATA_DEF(name)                                             \
    static int mnt ## name ## _new(lua_State *L)                        \
    {                                                                   \
        struct libmnt_ ## name **pp = newmnt ## name(L);                \
        *pp = mnt_new_ ## name();                                       \
        if (*pp == NULL)                                                \
            lua_pushnil(L);                                             \
        return 1;                                                       \
    }                                                                   \
    static int mnt ## name ## _free(lua_State *L)                       \
    {                                                                   \
        struct libmnt_ ## name **pp = tomnt ## name ## p(L, 1);         \
        if (*pp) {                                                      \
            mnt_free_ ## name(*pp);                                     \
            *pp = NULL;                                                 \
        }                                                               \
        return 0;                                                       \
    }

#define MNT_UDATA_GC(name)                                              \
    static int mnt ## name ## _unref(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## name *p = tomnt ## name(L, 1);                \
        mnt_unref_ ## name(p);                                          \
        return 0;                                                       \
    }


MNT_UDATA_DEF(fs)
MNT_UDATA_DEF(table)
MNT_UDATA_DEF(context)
MNT_UDATA_DEF(cache)
MNT_UDATA_GC(fs)
MNT_UDATA_GC(table)
MNT_UDATA_GC(cache)


#define MNT_METH_FUNC(c, name, type)                                    \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        if (lua_gettop(L) == 1) {                                       \
            lua_push ## type(L, mnt_ ## c ## _get_ ## name(p));         \
            return 1;                                                   \
        } else {                                                        \
            int err;    /* TODO */                                      \
            err = mnt_ ## c ## _set_ ## name(p, lua_to ## type(L, 2));  \
            return mnt_result(L, err);                                  \
        }                                                               \
    }

#define MNT_METH_GET(c, name, type)                                     \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        lua_push ## type(L, mnt_ ## c ## _get_ ## name(p));             \
        return 1;                                                       \
    }

#define MNT_METH_R0(c, name, rtype)                                     \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        lua_push ## rtype(L, mnt_ ## c ## _ ## name(p));                \
        return 1;                                                       \
    }

#define MNT_METH_R1(c, name, rtype, ctype, lfunc)                       \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        ctype arg = lfunc(L, 2);                                        \
        lua_push ## rtype(L, mnt_ ## c ## _ ## name(p, arg));           \
        return 1;                                                       \
    }

#define MNT_METH_OP0(c, name)                                           \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        int err = mnt_ ## c ## _ ## name(p);                            \
        return mnt_result(L, err);                                      \
    }

#define MNT_METH_OP1(c, name, ctype, lfunc)                             \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        ctype arg = lfunc(L, 2);                                        \
        int err = mnt_ ## c ## _ ## name(p, arg);                       \
        return mnt_result(L, err);                                      \
    }


#define MNT_METH_R1S(c, name, rtype)    \
    MNT_METH_R1(c, name, rtype, const char *, luaL_checkstring)
#define MNT_METH_OP1S(c, name)          \
    MNT_METH_OP1(c, name, const char *, luaL_checkstring)
#define MNT_METH_OP1I(c, name)          \
    MNT_METH_OP1(c, name, int, luaL_checkinteger)
#define MNT_METH_OP1C(c, name, c1)      \
    MNT_METH_OP1(c, name, struct libmnt_ ## c1 *, tomnt ## c1)

/*********************************** iter ***********************************/

static int mntiter_free(lua_State *L)
{
    struct libmnt_iter **pp = tomntiterp(L, 1);
    if (*pp) {
        mnt_free_iter(*pp);
        *pp = NULL;
    }
    return 0;
}

static const luaL_Reg mntiter_meth[] = {
    { "free",  mntiter_free  },
    { "__gc",  mntiter_free  },
    { NULL, NULL }
};

/********************************** cache ***********************************/

static int mntcache_device_has_tag(lua_State *L)
{
    struct libmnt_cache *cache = tomntcache(L, 1);
    const char *devname = luaL_checkstring(L, 2);
    const char *token = luaL_checkstring(L, 3);
    const char *value = luaL_checkstring(L, 4);
    lua_pushboolean(L, mnt_cache_device_has_tag(cache, devname, token, value));
    return 1;
}

static int mntcache_find_tag_value(lua_State *L)
{
    struct libmnt_cache *cache = tomntcache(L, 1);
    const char *devname = luaL_checkstring(L, 2);
    const char *token = luaL_checkstring(L, 3);
    const char *result = mnt_cache_find_tag_value(cache, devname, token);
    if (result)
        lua_pushstring(L, result);
    else
        lua_pushnil(L);
    return 1;
}

static int mntcache_read_tags(lua_State *L)
{
    struct libmnt_cache *cache = tomntcache(L, 1);
    const char *devname = luaL_checkstring(L, 2);
    int r = mnt_cache_read_tags(cache, devname);
    return mnt_result(L, r);
}

static int mntcache_set_targets(lua_State *L)
{
    struct libmnt_cache *cache = tomntcache(L, 1);
    struct libmnt_table *mtab = tomnttable(L, 2);
    int err = mnt_cache_set_targets(cache, mtab);
    return mnt_result(L, err);
}


static const luaL_Reg mntcache_meth[] = {
    { "free",           mntcache_free           },
    { "__gc",           mntcache_unref          },
    { "device_has_tag", mntcache_device_has_tag },
    { "find_tag_value", mntcache_find_tag_value },
    { "set_targets",    mntcache_set_targets    },
    { NULL, NULL }
};

/********************************** table ***********************************/

static int mnttable_new_from_dir(lua_State *L)
{
    const char *s = luaL_checkstring(L, 1);
    struct libmnt_table **tablep = newmnttable(L);
    *tablep = mnt_new_table_from_dir(s);
    if (*tablep == NULL)
        lua_pushnil(L);
    return 1;
}

static int mnttable_new_from_file(lua_State *L)
{
    const char *s = luaL_checkstring(L, 1);
    struct libmnt_table **tablep = newmnttable(L);
    *tablep = mnt_new_table_from_file(s);
    if (*tablep == NULL)
        lua_pushnil(L);
    return 1;
}

static int mnttable_enable_comments(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, 1);
    int enable = lua_gettop(L) < 2 ? true : lua_toboolean(L, 2);
    mnt_table_enable_comments(tb, enable);
    return 0;
}

static int mnttable_find_devno(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, 1);
    dev_t devno = (dev_t)luaL_checkinteger(L, 2);
    int d = lua_toboolean(L, 3) ? MNT_ITER_BACKWARD : MNT_ITER_FORWARD;
    struct libmnt_fs **fsp = newmntfs(L);
    *fsp = mnt_table_find_devno(tb, devno, d);
    if (*fsp == NULL)
        lua_pushnil(L);
    mnt_ref_fs(*fsp);
    return 1;
}

static int mnttable_cache(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, 1);
    if (lua_gettop(L) == 1) {
        struct libmnt_cache **cachep = newmntcache(L);
        *cachep = mnt_table_get_cache(tb);
        if (*cachep == NULL)
            lua_pushnil(L);
        mnt_ref_cache(*cachep);
        return 1;
    } else {
        struct libmnt_cache *cache = tomntcache(L, 2);
        int err = mnt_table_set_cache(tb, cache);
        return mnt_result(L, err);
    }
}

static int mnttable_nents(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, 1);
    lua_pushinteger(L, mnt_table_get_nents(tb));
    return 1;
}

static int mnttable_is_fs_mounted(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, 1);
    struct libmnt_fs *fs = tomntfs(L, 2);
    lua_pushboolean(L, mnt_table_is_fs_mounted(tb, fs));
    return 1;
}

static int mnttable_set_iter(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, 1);
    struct libmnt_iter *iter = tomntiter(L, 2);
    struct libmnt_fs *fs = tomntfs(L, 3);
    int err = mnt_table_set_iter(tb, iter, fs);
    return mnt_result(L, err);
}

static int mnttable_child_fs_next(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, lua_upvalueindex(1));
    struct libmnt_fs *parent = tomntfs(L, lua_upvalueindex(2));
    struct libmnt_iter *iter = tomntiter(L, lua_upvalueindex(3));
    struct libmnt_fs **fsp = newmntfs(L);
    int err = mnt_table_next_child_fs(tb, iter, parent, fsp);
    if (err)
        lua_pushnil(L);
    mnt_ref_fs(*fsp);
    return 1;
}

static int mnttable_child_fs(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, 1);
    struct libmnt_fs *fs = tomntfs(L, 2);
    struct libmnt_iter **iterp;
    int backward = lua_toboolean(L, 3);
    lua_settop(L, 2);
    iterp = newmntiter(L);
    *iterp = mnt_new_iter(backward ? MNT_ITER_BACKWARD : MNT_ITER_FORWARD);
    if (*iterp)
        lua_pushcclosure(L, mnttable_child_fs_next, 3); /* uv: [tb, fs, iter] */
    else
        lua_pushnil(L);
    return 1;
}

static int mnttable_fs_next(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, lua_upvalueindex(1));
    struct libmnt_iter *iter = tomntiter(L, lua_upvalueindex(2));
    struct libmnt_fs **fsp = newmntfs(L);
    int err = mnt_table_next_fs(tb, iter, fsp);
    if (err)
        lua_pushnil(L);
    mnt_ref_fs(*fsp);
    return 1;
}

static int mnttable_fs(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, 1);
    struct libmnt_iter **iterp;
    int backward = lua_toboolean(L, 2);
    lua_settop(L, 1);
    iterp = newmntiter(L);
    *iterp = mnt_new_iter(backward ? MNT_ITER_BACKWARD : MNT_ITER_FORWARD);
    if (*iterp)
        lua_pushcclosure(L, mnttable_fs_next, 2);   /* uv: [tb, iter] */
    else
        lua_pushnil(L);
    return 1;
}

#if LIBMOUNT_MAJOR_VERSION > 2 || LIBMOUNT_MINOR_VERSION >= 34

static int mnttable_find_fs(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, 1);
    struct libmnt_fs *fs = tomntfs(L, 2);
    int idx = mnt_table_find_fs(tb, fs);
    return mnt_result(L, idx);
}

static int mnttable_insert_fs(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, 1);
    int before = lua_toboolean(L, 2);
    struct libmnt_fs *pos = tomntfs(L, 3);
    struct libmnt_fs *fs = tomntfs(L, 4);
    int err = mnt_table_insert_fs(tb, before, pos, fs);
    return mnt_result(L, err);
}

static int mnttable_move_fs(lua_State *L)
{
    struct libmnt_table *src = tomnttable(L, 1);
    struct libmnt_table *dst = tomnttable(L, 2);
    int before = lua_toboolean(L, 3);
    struct libmnt_fs *pos = tomntfs(L, 4);
    struct libmnt_fs *fs = tomntfs(L, 5);
    int err = mnt_table_move_fs(src, dst, before, pos, fs);
    return mnt_result(L, err);
}

static int mnttable_over_fs_next(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, lua_upvalueindex(1));
    struct libmnt_fs **parent = lua_touserdata(L, lua_upvalueindex(2));
    struct libmnt_fs **childp = newmntfs(L);
    int err = mnt_table_over_fs(tb, *parent, childp);
    if (!err) {
        mnt_ref_fs(*childp);
        *parent = *childp;
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int mnttable_over_fs(lua_State *L)
{
    struct libmnt_table *tb = tomnttable(L, 1);
    struct libmnt_fs *fs = tomntfs(L, 2);
    lua_settop(L, 1);
    *(struct libmnt_fs **)lua_newuserdata(L, sizeof(struct libmnt_fs *)) = fs;
    /* uv: [tb, parent] */
    lua_pushcclosure(L, mnttable_over_fs_next, 2);
    return 1;
}

#endif


#define MNT_METH_FIND1(c, name)                                         \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        const char *s = luaL_checkstring(L, 2);                         \
        int d = lua_toboolean(L, 3) ? MNT_ITER_BACKWARD : MNT_ITER_FORWARD; \
        struct libmnt_fs **fsp = newmntfs(L);                           \
        *fsp = mnt_ ## c ## _ ## name(p, s, d);                         \
        if (*fsp == NULL)                                               \
            lua_pushnil(L);                                             \
        mnt_ref_fs(*fsp);                                               \
        return 1;                                                       \
    }

#define MNT_METH_FIND2(c, name)                                         \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        const char *s1 = luaL_checkstring(L, 2);                        \
        const char *s2 = luaL_checkstring(L, 3);                        \
        int d = lua_toboolean(L, 4) ? MNT_ITER_BACKWARD : MNT_ITER_FORWARD; \
        struct libmnt_fs **fsp = newmntfs(L);                           \
        *fsp = mnt_ ## c ## _ ## name(p, s1, s2, d);                    \
        if (*fsp == NULL)                                               \
            lua_pushnil(L);                                             \
        mnt_ref_fs(*fsp);                                               \
        return 1;                                                       \
    }

#define MNT_METH_FIND3(c, name)                                         \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        const char *s1 = luaL_checkstring(L, 2);                        \
        const char *s2 = luaL_checkstring(L, 3);                        \
        const char *s3 = luaL_checkstring(L, 4);                        \
        int d = lua_toboolean(L, 5) ? MNT_ITER_BACKWARD : MNT_ITER_FORWARD; \
        struct libmnt_fs **fsp = newmntfs(L);                           \
        *fsp = mnt_ ## c ## _ ## name(p, s1, s2, s3, d);                \
        if (*fsp == NULL)                                               \
            lua_pushnil(L);                                             \
        mnt_ref_fs(*fsp);                                               \
        return 1;                                                       \
    }

#define MNT_METH_FS(c, name)                                            \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        struct libmnt_fs **fsp = newmntfs(L);                           \
        int err = mnt_ ## c ## _ ## name(p, fsp);                       \
        if (err)                                                        \
            lua_pushnil(L);                                             \
        mnt_ref_fs(*fsp);                                               \
        return 1;                                                       \
    }

#define MNT_METH_FS_OP(c, name)                                         \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        struct libmnt_fs *fs = tomntfs(L, 2);                           \
        int err = mnt_ ## c ## _ ## name(p, fs);                        \
        return mnt_result(L, err);                                      \
    }


#define MNTTABLE_METH_LISTS                                             \
    XX(MNT_METH_FIND1,  table, find_mountpoint)                         \
    XX(MNT_METH_FIND1,  table, find_source)                             \
    XX(MNT_METH_FIND1,  table, find_srcpath)                            \
    XX(MNT_METH_FIND1,  table, find_target)                             \
    XX(MNT_METH_FIND2,  table, find_pair)                               \
    XX(MNT_METH_FIND2,  table, find_tag)                                \
    XX(MNT_METH_FIND3,  table, find_target_with_option)                 \
    XX(MNT_METH_FS,     table, first_fs)                                \
    XX(MNT_METH_FS,     table, last_fs)                                 \
    XX(MNT_METH_FS,     table, get_root_fs)                             \
    XX(MNT_METH_FS_OP,  table, add_fs)                                  \
    XX(MNT_METH_FS_OP,  table, remove_fs)                               \
    XX(MNT_METH_FUNC,   table, intro_comment,       string)             \
    XX(MNT_METH_FUNC,   table, trailing_comment,    string)             \
    XX(MNT_METH_R0,     table, is_empty,            boolean)            \
    XX(MNT_METH_R0,     table, with_comments,       boolean)            \
    XX(MNT_METH_OP1S,   table, append_intro_comment)                    \
    XX(MNT_METH_OP1S,   table, append_trailing_comment)                 \
    XX(MNT_METH_OP1S,   table, set_intro_comment)                       \
    XX(MNT_METH_OP1S,   table, set_trailing_comment)                    \
    XX(MNT_METH_OP1S,   table, parse_dir)                               \
    XX(MNT_METH_OP1S,   table, parse_file)                              \
    XX(MNT_METH_OP1S,   table, parse_fstab)                             \
    XX(MNT_METH_OP1S,   table, parse_mtab)                              \
    XX(MNT_METH_OP1S,   table, parse_swaps)

#define XX(macro, c, name, ...)     macro(c, name, ##__VA_ARGS__)
MNTTABLE_METH_LISTS
#undef XX

static const luaL_Reg mnttable_meth[] = {
    { "free",            mnttable_free            },
    { "__gc",            mnttable_unref           },
    { "enable_comments", mnttable_enable_comments },
    { "find_devno",      mnttable_find_devno      },
    { "cache",           mnttable_cache           },
    { "nents",           mnttable_nents           },
    { "is_fs_mounted",   mnttable_is_fs_mounted   },
    { "set_iter",        mnttable_set_iter        },
    { "child_fs",        mnttable_child_fs        },
    { "fs",              mnttable_fs              },
#if LIBMOUNT_MAJOR_VERSION > 2 || LIBMOUNT_MINOR_VERSION >= 34
    { "find_fs",         mnttable_find_fs         },
    { "insert_fs",       mnttable_insert_fs       },
    { "move_fs",         mnttable_move_fs         },
    { "over_fs",         mnttable_over_fs         },
#endif

#define XX(macro, c, name, ...)     { #name, mnt ## c ## _ ## name },
MNTTABLE_METH_LISTS
#undef XX
    { NULL, NULL }
};

/******************************** filesystem ********************************/

#define MNT_METH_MATCH_CACHE(c, name)                                   \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        const char *s = luaL_checkstring(L, 2);                         \
        struct libmnt_cache *cache = tomntcache(L, 3);                  \
        int b = mnt_ ## c ## _ ## name(p, s, cache);                    \
        lua_pushboolean(L, b);                                          \
        return 1;                                                       \
    }


#define MNTFS_METH_LISTS                                                \
    XX(MNT_METH_FUNC,        fs, attributes,      string)               \
    XX(MNT_METH_FUNC,        fs, bindsrc,         string)               \
    XX(MNT_METH_FUNC,        fs, comment,         string)               \
    XX(MNT_METH_FUNC,        fs, freq,            integer)              \
    XX(MNT_METH_FUNC,        fs, fstype,          string)               \
    XX(MNT_METH_FUNC,        fs, options,         string)               \
    XX(MNT_METH_FUNC,        fs, passno,          integer)              \
    XX(MNT_METH_FUNC,        fs, priority,        integer)              \
    XX(MNT_METH_FUNC,        fs, root,            string)               \
    XX(MNT_METH_FUNC,        fs, source,          string)               \
    XX(MNT_METH_FUNC,        fs, target,          string)               \
    XX(MNT_METH_GET,         fs, devno,           integer)              \
    XX(MNT_METH_GET,         fs, fs_options,      string)               \
    XX(MNT_METH_GET,         fs, id,              integer)              \
    XX(MNT_METH_GET,         fs, optional_fields, string)               \
    XX(MNT_METH_GET,         fs, parent_id,       integer)              \
    XX(MNT_METH_GET,         fs, size,            number)               \
    XX(MNT_METH_GET,         fs, srcpath,         string)               \
    XX(MNT_METH_GET,         fs, swaptype,        string)               \
    XX(MNT_METH_GET,         fs, tid,             integer)              \
    XX(MNT_METH_GET,         fs, usedsize,        number)               \
    XX(MNT_METH_GET,         fs, user_options,    string)               \
    XX(MNT_METH_GET,         fs, vfs_options,     string)               \
    XX(MNT_METH_GET,         fs, vfs_options_all, string)               \
    XX(MNT_METH_OP1S,        fs, append_attributes)                     \
    XX(MNT_METH_OP1S,        fs, prepend_attributes)                    \
    XX(MNT_METH_OP1S,        fs, append_options)                        \
    XX(MNT_METH_OP1S,        fs, prepend_options)                       \
    XX(MNT_METH_OP1S,        fs, append_comment)                        \
    XX(MNT_METH_R1S,         fs, match_fstype,  boolean)                \
    XX(MNT_METH_R1S,         fs, match_options, boolean)                \
    XX(MNT_METH_R1S,         fs, streq_srcpath, boolean)                \
    XX(MNT_METH_R1S,         fs, streq_target,  boolean)                \
    XX(MNT_METH_MATCH_CACHE, fs, match_source)                          \
    XX(MNT_METH_MATCH_CACHE, fs, match_target)                          \
    XX(MNT_METH_R0,          fs, is_kernel,     boolean)                \
    XX(MNT_METH_R0,          fs, is_netfs,      boolean)                \
    XX(MNT_METH_R0,          fs, is_pseudofs,   boolean)                \
    XX(MNT_METH_R0,          fs, is_swaparea,   boolean)

#define XX(macro, c, name, ...)     macro(c, name, ##__VA_ARGS__)
MNTFS_METH_LISTS
#undef XX

static const luaL_Reg mntfs_meth[] = {
    { "free",   mntfs_free  },
    { "__gc",   mntfs_unref },

#define XX(macro, c, name, ...)     { #name, mnt ## c ## _ ## name },
MNTFS_METH_LISTS
#undef XX
    { NULL, NULL }
};

/**************************** high-level context ****************************/

static int mntcontext_get_mtab(lua_State *L)
{
    struct libmnt_context *ctx = tomntcontext(L, 1);
    struct libmnt_table **tbp = newmnttable(L);
    int err = mnt_context_get_mtab(ctx, tbp);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    mnt_ref_table(*tbp);
    return 1;
}

static int mntcontext_get_table(lua_State *L)
{
    struct libmnt_context *ctx = tomntcontext(L, 1);
    const char *filename = luaL_checkstring(L, 2);
    struct libmnt_table **tbp = newmnttable(L);
    int err = mnt_context_get_table(ctx, filename, tbp);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    mnt_ref_table(*tbp);
    return 1;
}

static int mntcontext_is_fs_mounted(lua_State *L)
{
    struct libmnt_context *ctx = tomntcontext(L, 1);
    struct libmnt_fs *fs = tomntfs(L, 2);
    int mounted;
    int err = mnt_context_is_fs_mounted(ctx, fs, &mounted);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    } else {
        lua_pushboolean(L, mounted);
        return 1;
    }
}

static int mntcontext_wait_for_children(lua_State *L)
{
    struct libmnt_context *ctx = tomntcontext(L, 1);
    int nchildren = 0, nerrs = 0;
    int err = mnt_context_wait_for_children(ctx, &nchildren, &nerrs);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
    } else {
        lua_pushinteger(L, nchildren);
        lua_pushinteger(L, nerrs);
    }
    return 2;
}


#define MNT_METH_ENABLE(c, name)                                        \
    static int mnt ## c ## _ ## name(lua_State *L)                      \
    {                                                                   \
        struct libmnt_ ## c *p = tomnt ## c(L, 1);                      \
        int b = lua_gettop(L) < 2 ? true : lua_toboolean(L, 2);         \
        int err = mnt_ ## c ## _ ## name(p, b);                         \
        return mnt_result(L, err);                                      \
    }

#define MNT_METH_UINT(c, name)                                          \
    static int mntcontext_ ## name(lua_State *L)                        \
    {                                                                   \
        struct libmnt_context *ctx = tomntcontext(L, 1);                \
        unsigned long mflags;                                           \
        int err;                                                        \
        if (lua_gettop(L) == 1) {                                       \
            err = mnt_context_get_ ## name(ctx, &mflags);               \
            if (!err) {                                                 \
                lua_pushinteger(L, mflags);                             \
                return 1;                                               \
            }                                                           \
        } else {                                                        \
            mflags = (unsigned long)luaL_checkinteger(L, 2);            \
            err = mnt_context_set_ ## name(ctx, mflags);                \
        }                                                               \
        return mnt_result(L, err);                                      \
    }

#if LIBMOUNT_MAJOR_VERSION > 2 || LIBMOUNT_MINOR_VERSION >= 33
#define LIST_2_33                                                       \
    XX(MNT_METH_OP1S,   context, set_target_ns)
#else
#define LIST_2_33
#endif

#if LIBMOUNT_MAJOR_VERSION > 2 || LIBMOUNT_MINOR_VERSION >= 35
#define LIST_2_35                                                       \
    XX(MNT_METH_OP0,    context, force_unrestricted)                    \
    XX(MNT_METH_FUNC,   context, target_prefix,     string)
#else
#define LIST_2_35
#endif

#define MNTCONTEXT_METH_LISTS                                           \
    XX(MNT_METH_ENABLE, context, disable_canonicalize)                  \
    XX(MNT_METH_ENABLE, context, disable_helpers)                       \
    XX(MNT_METH_ENABLE, context, disable_mtab)                          \
    XX(MNT_METH_ENABLE, context, disable_swapmatch)                     \
    XX(MNT_METH_ENABLE, context, enable_fake)                           \
    XX(MNT_METH_ENABLE, context, enable_force)                          \
    XX(MNT_METH_ENABLE, context, enable_fork)                           \
    XX(MNT_METH_ENABLE, context, enable_lazy)                           \
    XX(MNT_METH_ENABLE, context, enable_loopdel)                        \
    XX(MNT_METH_ENABLE, context, enable_rdonly_umount)                  \
    XX(MNT_METH_ENABLE, context, enable_rwonly_mount)                   \
    XX(MNT_METH_ENABLE, context, enable_sloppy)                         \
    XX(MNT_METH_ENABLE, context, enable_verbose)                        \
    XX(MNT_METH_OP1S,   context, append_options)                        \
    XX(MNT_METH_OP1S,   context, set_fstype_pattern)                    \
    XX(MNT_METH_OP1S,   context, set_options_pattern)                   \
    XX(MNT_METH_OP1I,   context, set_syscall_status)                    \
    XX(MNT_METH_OP0,    context, apply_fstab)                           \
    XX(MNT_METH_OP0,    context, reset_status)                          \
    XX(MNT_METH_FUNC,   context, fstype,            string)             \
    XX(MNT_METH_FUNC,   context, options,           string)             \
    XX(MNT_METH_FUNC,   context, source,            string)             \
    XX(MNT_METH_FUNC,   context, target,            string)             \
    XX(MNT_METH_FUNC,   context, optsmode,          integer)            \
    XX(MNT_METH_R0,     context, is_child,          boolean)            \
    XX(MNT_METH_R0,     context, is_fake,           boolean)            \
    XX(MNT_METH_R0,     context, is_force,          boolean)            \
    XX(MNT_METH_R0,     context, is_fork,           boolean)            \
    XX(MNT_METH_R0,     context, is_lazy,           boolean)            \
    XX(MNT_METH_R0,     context, is_loopdel,        boolean)            \
    XX(MNT_METH_R0,     context, is_nocanonicalize, boolean)            \
    XX(MNT_METH_R0,     context, is_nohelpers,      boolean)            \
    XX(MNT_METH_R0,     context, is_nomtab,         boolean)            \
    XX(MNT_METH_R0,     context, is_parent,         boolean)            \
    XX(MNT_METH_R0,     context, is_rdonly_umount,  boolean)            \
    XX(MNT_METH_R0,     context, is_restricted,     boolean)            \
    XX(MNT_METH_R0,     context, is_rwonly_mount,   boolean)            \
    XX(MNT_METH_R0,     context, is_sloppy,         boolean)            \
    XX(MNT_METH_R0,     context, is_swapmatch,      boolean)            \
    XX(MNT_METH_R0,     context, is_verbose,        boolean)            \
    XX(MNT_METH_R0,     context, forced_rdonly,     boolean)            \
    XX(MNT_METH_R0,     context, syscall_called,    boolean)            \
    XX(MNT_METH_R0,     context, tab_applied,       boolean)            \
    XX(MNT_METH_R0,     context, helper_executed,   boolean)            \
    XX(MNT_METH_R0,     context, get_status,        integer)            \
    XX(MNT_METH_R0,     context, get_syscall_errno, integer)            \
    XX(MNT_METH_R0,     context, get_helper_status, integer)            \
    XX(MNT_METH_OP1C,   context, set_cache,         cache)              \
    XX(MNT_METH_OP1C,   context, set_fs,            fs)                 \
    XX(MNT_METH_OP1C,   context, set_fstab,         table)              \
    XX(MNT_METH_UINT,   context, mflags)                                \
    XX(MNT_METH_UINT,   context, user_mflags)                           \
    LIST_2_33                                                           \
    LIST_2_35

#define XX(macro, c, name, ...)     macro(c, name, ##__VA_ARGS__)
MNTCONTEXT_METH_LISTS
#undef XX

static const luaL_Reg mntcontext_meth[] = {
    { "free",              mntcontext_free              },
    { "__gc",              mntcontext_free              },
    { "get_mtab",          mntcontext_get_mtab          },
    { "get_table",         mntcontext_get_table         },
    { "is_fs_mounted",     mntcontext_is_fs_mounted     },
    { "wait_for_children", mntcontext_wait_for_children },

#define XX(macro, c, name, ...)     { #name, mnt ## c ## _ ## name },
MNTCONTEXT_METH_LISTS
#undef XX
    { NULL, NULL }
};

/********************************** mount ***********************************/

static int mnt_version(lua_State *L)
{
    const char *s;
    int version = mnt_get_library_version(&s);
    lua_pushstring(L, s);
    return 1;
}

static int mnt_features(lua_State *L)
{
    const char **features;
    int n = mnt_get_library_features(&features);
    int i;
    if (n <= 0)
        return 0;
    lua_createtable(L, n, 0);
    for (i = 0; i < n; i++) {
        lua_pushstring(L, features[i]);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

static int mntmisc_mountpoint(lua_State *L)
{
    const char *path = luaL_checkstring(L, 1);
    char *mp = mnt_get_mountpoint(path);
    if (mp) {
        lua_pushstring(L, mp);
        free(mp);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int mntmisc_match_fstype(lua_State *L)
{
    const char *type = luaL_checkstring(L, 1);
    const char *pattern = luaL_optstring(L, 2, NULL);
    lua_pushboolean(L, mnt_match_fstype(type, pattern));
    return 1;
}

#define MNTMISC_METH_ARG0(name, ltype)                                  \
    static int mntmisc_ ## name(lua_State *L)                           \
    {                                                                   \
        lua_push ## ltype(L, mnt_ ## name());                           \
        return 1;                                                       \
    }

#define MNTMISC_METH_ARG1(name, ltype)                                  \
    static int mntmisc_ ## name(lua_State *L)                           \
    {                                                                   \
        const char *s = luaL_checkstring(L, 1);                         \
        lua_push ## ltype(L, mnt_ ## name(s));                          \
        return 1;                                                       \
    }

MNTMISC_METH_ARG0(get_fstab_path,       string)
MNTMISC_METH_ARG0(get_mtab_path,        string)
MNTMISC_METH_ARG0(get_swaps_path,       string)
MNTMISC_METH_ARG1(fstype_is_netfs,      boolean)
MNTMISC_METH_ARG1(fstype_is_pseudofs,   boolean)
MNTMISC_METH_ARG1(tag_is_valid,         boolean)
MNTMISC_METH_ARG1(mangle,               string)
MNTMISC_METH_ARG1(unmangle,             string)


static const luaL_Reg mountlib[] = {
    { "new_fs",              mntfs_new                  },
    { "new_table",           mnttable_new               },
    { "new_table_from_dir",  mnttable_new_from_dir      },
    { "new_table_from_file", mnttable_new_from_file     },
    { "new_context",         mntcontext_new             },
    { "new_cache",           mntcache_new               },
    { "version",             mnt_version                },
    { "features",            mnt_features               },
    { "mountpoint",          mntmisc_mountpoint         },
    { "match_fstype",        mntmisc_match_fstype       },
    { "fstab_path",          mntmisc_get_fstab_path     },
    { "mtab_path",           mntmisc_get_mtab_path      },
    { "swaps_path",          mntmisc_get_swaps_path     },
    { "fstype_is_netfs",     mntmisc_fstype_is_netfs    },
    { "fstype_is_pseudofs",  mntmisc_fstype_is_pseudofs },
    { "tag_is_valid",        mntmisc_tag_is_valid       },
    { "mangle",              mntmisc_mangle             },
    { "unmangle",            mntmisc_unmangle           },
    { NULL, NULL }
};

LUALIB_API int luaopen_mount(lua_State *L)
{
    luaL_newlib(L, mountlib);

    createmeta(L, METH_MOUNT_MNT_FS,      mntfs_meth);
    createmeta(L, METH_MOUNT_MNT_TABLE,   mnttable_meth);
    createmeta(L, METH_MOUNT_MNT_CONTEXT, mntcontext_meth);
    createmeta(L, METH_MOUNT_MNT_CACHE,   mntcache_meth);
    createmeta(L, METH_MOUNT_MNT_ITER,    mntiter_meth);

    return 1;
}
