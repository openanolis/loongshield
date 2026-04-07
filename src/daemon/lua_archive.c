#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <compat-5.3.h>

#include "luauxlib.h"

#include <archive.h>
#include <archive_entry.h>


#define METH_ARCHIVE_READ       "meth_archive_read"
#define METH_ARCHIVE_WRITE      "meth_archive_write"
#define METH_ARCHIVE_ENTRY      "meth_archive_entry"
#define METH_ARCHIVE_REGISTRY   "meth_archive_registry"


#define newpread(L)  (struct archive **)newcptr((L), METH_ARCHIVE_READ)
#define newpwrite(L) (struct archive **)newcptr((L), METH_ARCHIVE_WRITE)
#define newpentry(L) (struct archive_entry **)newcptr((L), METH_ARCHIVE_ENTRY)

#define topread(L, idx)     \
    (struct archive **)luaL_checkudata((L), (idx), METH_ARCHIVE_READ)
#define topwrite(L, idx)    \
    (struct archive **)luaL_checkudata((L), (idx), METH_ARCHIVE_WRITE)
#define topentry(L, idx)    \
    (struct archive_entry **)luaL_checkudata((L), (idx), METH_ARCHIVE_ENTRY)

#define toread(L, idx)      (*topread(L, idx))
#define towrite(L, idx)     (*topwrite(L, idx))
#define toentry(L, idx)     (*topentry(L, idx))


static int archive_error(lua_State *L, struct archive *a, const char *err)
{
    lua_pushnil(L);
    if (a)
        lua_pushstring(L, archive_error_string(a));
    else
        lua_pushstring(L, err);
    return 2;
}

/******************************** registry ********************************/

/*
 * store userdata to registry metatable:
 *   registry[ptr] = userdata
 *
 * access userdata from registry metatable
 */
static void registry_set(lua_State *L, void *ptr)
{
    luaL_checktype(L, -1, LUA_TUSERDATA);
    luaL_getmetatable(L, METH_ARCHIVE_REGISTRY);
    lua_pushlightuserdata(L, ptr);
    lua_pushvalue(L, -3);   /* stack: [userdata, registry, ptr, userdata] */
    lua_rawset(L, -3);      /* registry[ptr] = userdata */
    lua_pop(L, 1);
}

static int registry_get(lua_State *L, void *ptr)
{
    luaL_getmetatable(L, METH_ARCHIVE_REGISTRY);
    lua_pushlightuserdata(L, ptr);
    lua_rawget(L, -2);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 2);
        return 0;
    }
    lua_insert(L, -2);
    lua_pop(L, 1);
    return 1;
}

static void registry_init(lua_State *L, const char *tname)
{
    luaL_newmetatable(L, tname);

    /* setmetatable(mt, mt) */
    lua_pushvalue(L, -1);
    lua_setmetatable(L, -2);

    /* mt.__mode = 'v' */
    lua_pushliteral(L, "v");
    lua_setfield(L, -2, "__mode");

    lua_pop(L, 1);
}

/******************************** entry ********************************/

static int entry_free(lua_State *L)
{
    struct archive_entry **ee = topentry(L, 1);
    if (*ee) {
        archive_entry_free(*ee);
        *ee = NULL;
    }
    return 0;
}

static int entry_fflags(lua_State *L)
{
    struct archive_entry *e = toentry(L, 1);
    int top = lua_gettop(L);
    lua_pushstring(L, archive_entry_fflags_text(e));
    if (top == 2) {
        const char *s = archive_entry_copy_fflags_text(e, lua_tostring(L, 2));
        if (s)
            luaL_error(L, "invalid fflags: '%s' is not a known fflag", s);
    }
    return 1;
}

static int entry_size(lua_State *L)
{
    struct archive_entry *e = toentry(L, 1);
    int top = lua_gettop(L);

    if (archive_entry_size_is_set(e))
        lua_pushnumber(L, archive_entry_size(e));
    else
        lua_pushnil(L);

    if (top == 2) {
        if (lua_isnil(L, 2))
            archive_entry_unset_size(e);
        else
            archive_entry_set_size(e, lua_tonumber(L, 2));
    }
    return 1;
}

static int entry_filetype(lua_State *L)
{
    static const struct cflag_opt opts[] = {
        { "reg",  AE_IFREG  },
        { "lnk",  AE_IFLNK  },
        { "sock", AE_IFSOCK },
        { "chr",  AE_IFCHR  },
        { "blk",  AE_IFBLK  },
        { "dir",  AE_IFDIR  },
        { "fifo", AE_IFIFO  },
        { NULL, 0 }
    };
    struct archive_entry *e = toentry(L, 1);
    int top = lua_gettop(L);
    unsigned int ft;
    const char *s;

    ft = archive_entry_filetype(e);
    if ((s = fromcflags(opts, ft & AE_IFMT, NULL)) != NULL)
        lua_pushstring(L, s);
    else
        lua_pushnil(L);

    if (top == 2) {
        ft = tocflags(L, 2, opts, (unsigned int)AE_IFREG);
        archive_entry_set_filetype(e, ft);
    }

    return 1;
}

#define DEF_ENTRY_METH(name, type, op)                                      \
    static int entry_ ## name(lua_State *L)                                 \
    {                                                                       \
        struct archive_entry *e = toentry(L, 1);                            \
        int top = lua_gettop(L);                                            \
        lua_push ## type(L, archive_entry_ ## name(e));                     \
        if (top == 2)                                                       \
            archive_entry_ ## op ## _ ## name(e, lua_to ## type(L, 2));     \
        return 1;                                                           \
    }

#define DEF_ENTRY_TIME_METH(time)                                           \
    static int entry_ ## time(lua_State *L)                                 \
    {                                                                       \
        struct archive_entry *e = toentry(L, 1);                            \
        int top = lua_gettop(L);                                            \
        int nres = 0;                                                       \
                                                                            \
        if (archive_entry_ ## time ## _is_set(e)) {                         \
            lua_pushnumber(L, archive_entry_ ## time(e));                   \
            lua_pushnumber(L, archive_entry_ ## time ## _nsec(e));          \
            nres = 2;                                                       \
        }                                                                   \
                                                                            \
        if (top >= 2) {                                                     \
            if (lua_isnil(L, 2)) {                                          \
                archive_entry_unset_ ## time(e);                            \
            } else if (lua_istable(L, 2)) {                                 \
                lua_rawgeti(L, 2, 1);                                       \
                lua_rawgeti(L, 2, 2);                                       \
                archive_entry_set_ ## time(e, lua_tonumber(L, -2),          \
                                              lua_tonumber(L, -1));         \
            } else {                                                        \
                archive_entry_set_ ## time(e, lua_tonumber(L, 2),           \
                                              lua_tonumber(L, 3));          \
            }                                                               \
        }                                                                   \
        return nres;                                                        \
    }

#define DEF_ENTRY_BITS_METH(name, type, op, retname, rettype)               \
    static int entry_ ## name(lua_State *L)                                 \
    {                                                                       \
        struct archive_entry *e = toentry(L, 1);                            \
        int top = lua_gettop(L);                                            \
        const char *s1;                                                     \
        char *s2;                                                           \
        unsigned long n;                                                    \
        int base = 10;                                                      \
                                                                            \
        lua_push ## rettype(L, archive_entry_ ## retname(e));               \
        if (top == 2) {                                                     \
            switch (lua_type(L, 2)) {                                       \
            case LUA_TNUMBER:                                               \
                archive_entry_ ## op ## _ ## name(e, lua_to ## type(L, 2)); \
                break;                                                      \
                                                                            \
            case LUA_TSTRING:                                               \
                s1 = lua_tostring(L, 2);                                    \
                if (*s1 == '0') {                                           \
                    switch (*++s1) {                                        \
                    case 'b': case 'B': s1++; base = 2;  break;             \
                    case 'x': case 'X': s1++; base = 16; break;             \
                    default:                  base = 8;  break;             \
                    }                                                       \
                }                                                           \
                n = strtoul(s1, &s2, base);                                 \
                if (s1 != s2) {  /* at least one valid digit? */            \
                    while (isspace((int)(*s2)))                             \
                        s2++;  /* skip trailing spaces */                   \
                    if (*s2 == '\0') /* no invalid trailing characters? */  \
                        archive_entry_ ## op ## _ ## name(e, n);            \
                }                                                           \
                break;                                                      \
                                                                            \
            default:                                                        \
                luaL_error(L, "invalid type for second argument");          \
                break;                                                      \
            }                                                               \
        }                                                                   \
        return 1;                                                           \
    }


#define ENTRY_METH_LISTS                                                    \
    XX(DEF_ENTRY_METH, dev, number, set)                                    \
    XX(DEF_ENTRY_METH, rdev, number, set)                                   \
    XX(DEF_ENTRY_METH, ino, number, set)                                    \
    XX(DEF_ENTRY_METH, uid, number, set)                                    \
    XX(DEF_ENTRY_METH, gid, number, set)                                    \
    XX(DEF_ENTRY_METH, nlink, integer, set)                                 \
    XX(DEF_ENTRY_METH, uname, string, copy)                                 \
    XX(DEF_ENTRY_METH, gname, string, copy)                                 \
    XX(DEF_ENTRY_METH, symlink, string, copy)                               \
    XX(DEF_ENTRY_METH, hardlink, string, copy)                              \
    XX(DEF_ENTRY_METH, pathname, string, copy)                              \
    XX(DEF_ENTRY_METH, sourcepath, string, copy)                            \
    XX(DEF_ENTRY_TIME_METH, atime)                                          \
    XX(DEF_ENTRY_TIME_METH, mtime)                                          \
    XX(DEF_ENTRY_TIME_METH, ctime)                                          \
    XX(DEF_ENTRY_TIME_METH, birthtime)                                      \
    XX(DEF_ENTRY_BITS_METH, perm, number, set, perm, number)                \
    XX(DEF_ENTRY_BITS_METH, mode, number, set, strmode, string)

#define XX(MACRO, name, ...)    MACRO(name, ##__VA_ARGS__)
ENTRY_METH_LISTS
#undef XX

static const luaL_Reg entry_meth[] = {
    { "free",      entry_free      },
    { "__gc",      entry_free      },
    { "fflags",    entry_fflags    },
    { "size",      entry_size      },
    { "filetype",  entry_filetype  },

#define XX(macro, name, ...)    { #name, entry_ ## name },
    ENTRY_METH_LISTS
#undef XX
    { NULL, NULL }
};

static int archive_entry(lua_State *L)
{
    struct archive_entry **ee;

    ee = newpentry(L);
    *ee = archive_entry_new();
    if (*ee == NULL)
        return archive_error(L, NULL, "no memory");

    if (!lua_istable(L, 1))
        return 1;

    lua_getmetatable(L, -1);

    /* iterate over the table and call the metatable method with that name */
    lua_pushnil(L);
    while (lua_next(L, 1) != 0) {
        lua_pushvalue(L, -2);
        /* stack: [argstable, userdata, metatable, key, value, key] */
        lua_gettable(L, -4);        /* metatable[key] */
        if (lua_isnil(L, -1))
            luaL_error(L, "invalid argument: '%s' is not a valid field",
                       lua_tostring(L, -3));

        /* TODO: use FFI to call C function directly */
        lua_pushvalue(L, -5);
        lua_pushvalue(L, -3);
        /* stack: [argstable, userdata, metatable, key, value, func,
                   userdata, value] */
        lua_call(L, 2, 0);
        lua_pop(L, 1);
    }

    lua_pop(L, 1);      /* pop metatable */

    return 1;
}

/******************************* read & write *******************************/

/*
 * create an environment to store a reference to the callback
 */
static void store_to_fenv(lua_State *L, const char *name)
{
    lua_createtable(L, 0, 1);
    lua_getfield(L, 1, name);
    if (!lua_isfunction(L, -1))
        luaL_error(L, "required parameter '%s' must be a function", name);
    lua_setfield(L, -2, name);      /* fenv[name] = args[name] */
    lua_setfenv(L, -2);             /* setfenv for userdata */
}

static void load_from_fenv(lua_State *L, int idx, const char *name)
{
    lua_getfenv(L, idx);
    lua_pushstring(L, name);
    lua_rawget(L, -2);              /* fenv[name] */
    lua_insert(L, -2);
    lua_pop(L, 1);
}


struct named_setter {
    const char *name;
    int (*setter)(struct archive *a);
};

#define NS_LISTS                                        \
    DEF_NS(all,            rflt, rfmt,    _,    _)      \
    DEF_NS(bzip2,          rflt,    _, wflt,    _)      \
    DEF_NS(compress,       rflt,    _, wflt,    _)      \
    DEF_NS(gzip,           rflt,    _, wflt,    _)      \
    DEF_NS(grzip,          rflt,    _, wflt,    _)      \
    DEF_NS(lrzip,          rflt,    _, wflt,    _)      \
    DEF_NS(lz4,            rflt,    _, wflt,    _)      \
    DEF_NS(lzip,           rflt,    _, wflt,    _)      \
    DEF_NS(lzma,           rflt,    _, wflt,    _)      \
    DEF_NS(lzop,           rflt,    _, wflt,    _)      \
    DEF_NS(none,           rflt,    _, wflt,    _)      \
    DEF_NS(xz,             rflt,    _, wflt,    _)      \
    DEF_NS(zstd,           rflt,    _, wflt,    _)      \
    DEF_NS(rpm,            rflt,    _,    _,    _)      \
    DEF_NS(uu,             rflt,    _,    _,    _)      \
    DEF_NS(uuencode,          _,    _, wflt,    _)      \
    DEF_NS(b64encode,         _,    _, wflt,    _)      \
    DEF_NS(7zip,              _, rfmt,    _, wfmt)      \
    DEF_NS(ar,                _, rfmt,    _,    _)      \
    DEF_NS(ar_bsd,            _,    _,    _, wfmt)      \
    DEF_NS(ar_svr4,           _,    _,    _, wfmt)      \
    DEF_NS(cab,               _, rfmt,    _,    _)      \
    DEF_NS(cpio,              _, rfmt,    _, wfmt)      \
    DEF_NS(cpio_bin,          _,    _,    _, wfmt)      \
    DEF_NS(cpio_newc,         _,    _,    _, wfmt)      \
    DEF_NS(cpio_odc,          _,    _,    _, wfmt)      \
    DEF_NS(cpio_pwb,          _,    _,    _, wfmt)      \
    DEF_NS(empty,             _, rfmt,    _,    _)      \
    DEF_NS(gnutar,            _, rfmt,    _, wfmt)      \
    DEF_NS(iso9660,           _, rfmt,    _, wfmt)      \
    DEF_NS(lha,               _, rfmt,    _,    _)      \
    DEF_NS(mtree,             _, rfmt,    _, wfmt)      \
    DEF_NS(mtree_classic,     _,    _,    _, wfmt)      \
    DEF_NS(rar,               _, rfmt,    _,    _)      \
    DEF_NS(rar5,              _, rfmt,    _,    _)      \
    DEF_NS(raw,               _, rfmt,    _, wfmt)      \
    DEF_NS(tar,               _, rfmt,    _,    _)      \
    DEF_NS(warc,              _, rfmt,    _, wfmt)      \
    DEF_NS(xar,               _, rfmt,    _, wfmt)      \
    DEF_NS(zip,               _, rfmt,    _, wfmt)      \
    DEF_NS(zip_streamable,    _, rfmt,    _,    _)      \
    DEF_NS(zip_seekable,      _, rfmt,    _,    _)      \
    DEF_NS(pax,               _,    _,    _, wfmt)      \
    DEF_NS(pax_restricted,    _,    _,    _, wfmt)      \
    DEF_NS(shar,              _,    _,    _, wfmt)      \
    DEF_NS(shar_dump,         _,    _,    _, wfmt)      \
    DEF_NS(ustar,             _,    _,    _, wfmt)      \
    DEF_NS(v7tar,             _,    _,    _, wfmt)

#define _(name)
#define rflt(name)  { #name, archive_read_support_filter_ ## name },
#define rfmt(name)  { #name, archive_read_support_format_ ## name },
#define wflt(name)  { #name, archive_write_add_filter_ ## name },
#define wfmt(name)  { #name, archive_write_set_format_ ## name },

static struct named_setter ns_rfilters[] = {
#define DEF_NS(name, rflt, rfmt, wflt, wfmt)    rflt(name)
    NS_LISTS
#undef DEF_NS
    { NULL, NULL }
};

static struct named_setter ns_rformats[] = {
#define DEF_NS(name, rflt, rfmt, wflt, wfmt)    rfmt(name)
    NS_LISTS
#undef DEF_NS
    { NULL, NULL }
};

static struct named_setter ns_wfilters[] = {
#define DEF_NS(name, rflt, rfmt, wflt, wfmt)    wflt(name)
    NS_LISTS
#undef DEF_NS
    { NULL, NULL }
};

static struct named_setter ns_wformats[] = {
#define DEF_NS(name, rflt, rfmt, wflt, wfmt)    wfmt(name)
    NS_LISTS
#undef DEF_NS
    { NULL, NULL }
};

#undef _
#undef rflt
#undef rfmt
#undef wflt
#undef wfmt


static int do_setters(lua_State *L, struct archive *a, const char *field,
                      struct named_setter ns[], const char *name)
{
    const char *s = name;
    size_t len;
    int i;
    int nres = 0;

    for ( ; *s; s += len) {
        /* skip specical character */
        while (*s && !isalnum(*s))
            s++;

        if (!*s)
            break;

        /* calc length */
        for (len = 0; isalnum(s[len]); )
            len++;

        for (i = 0; ns[i].name; i++) {
            if (strncmp(s, ns[i].name, len) == 0)
                break;
        }

        if (ns[i].name == NULL) {
            lua_pushlstring(L, s, len);
            luaL_error(L, "No such %s '%s'", field, lua_tostring(L, -1));
        }

        if (ns[i].setter(a) != ARCHIVE_OK) {
            lua_pushlstring(L, s, len);
            luaL_error(L, "%s set to '%s' error: %s", field,
                       lua_tostring(L, -1), archive_error_string(a));
        }

        nres++;
    }

    return nres;
}

static void setoption(lua_State *L, struct archive *a, const char *field,
                      struct named_setter *ns, const char *d/*default*/)
{
    lua_getfield(L, 1, field);
    if (lua_tostring(L, -1) == NULL) {
        if (!d)
            luaL_error(L, "'%s' field is required", field);
        lua_pop(L, 1);
        lua_pushstring(L, d);
    }

    if (do_setters(L, a, field, ns, lua_tostring(L, -1)) == 0)
        luaL_error(L, "%s = '%s' is not allowed", field, lua_tostring(L, -1));

    lua_pop(L, 1);
}

static la_ssize_t
callback_read(struct archive *a, void *ud, const void **buffer)
{
    lua_State *L = (lua_State *)ud;
    size_t len;

    if (!registry_get(L, a)) {
        archive_set_error(a, 0,
                    "internal error: read callback called on archive "
                    "that should already have been garbage collected!");
        return -1;
    }

    /* make a call and get buffer: callback(usredata) */
    load_from_fenv(L, -1, "reader");
    lua_pushvalue(L, -2);
    /* stack: [userdata, callback, userdata] */
    if (lua_pcall(L, 1, 1, 0) != 0) {
        archive_set_error(a, 0, "%s", lua_tostring(L, -1));
        lua_pop(L, 2);
        return -1;
    }

    *buffer = lua_tolstring(L, -1, &len);
    if (*buffer == NULL)
        return 0;

    /*
     * We directly return the raw internal buffer, so we need to keep
     * a reference around:
     *   fenv["read_buffer"] = buffer
     */
    lua_getfenv(L, -2);
    lua_pushliteral(L, "read_buffer");
    lua_pushvalue(L, -3);
    /* stack: [userdata, buffer, fenv, "read_buffer", buffer] */
    lua_rawset(L, -3);
    lua_pop(L, 3);

    return len;
}

static la_ssize_t
callback_write(struct archive *a, void *ud, const void *buffer, size_t length)
{
    lua_State *L = (lua_State *)ud;
    size_t len;

    if (!registry_get(L, a)) {
        archive_set_error(a, 0,
                    "internal error: write callback called on archive "
                    "that should already have been garbage collected!");
        return -1;
    }

    /* make a call: callback(usredata, buffer) */
    load_from_fenv(L, -1, "writer");
    lua_pushvalue(L, -2);
    lua_pushlstring(L, (const char *)buffer, length);
    /* stack: [userdata, callback, userdata, buffer] */
    if (lua_pcall(L, 2, 1, 0) != 0) {
        archive_set_error(a, 0, "%s", lua_tostring(L, -1));
        lua_pop(L, 2);
        return -1;
    }

    len = lua_tointeger(L, -1);
    lua_pop(L, 2);

    return len;
}

#define SET_AR_FIELD(rw, field, type)                                       \
    lua_getfield(L, 1, #field);                                             \
    if (!lua_isnil(L, -1)) {                                                \
        int ret;                                                            \
        ret = archive_ ## rw ## _set_ ## field(*a, lua_to ## type(L, -1));  \
        if (ret != ARCHIVE_OK)                                              \
            luaL_error(L, #field " = '%s' is not allowed, %s",              \
                       lua_tostring(L, -1), archive_error_string(*a));      \
    }                                                                       \
    lua_pop(L, 1);

static int archive_read(lua_State *L)
{
    struct archive **a;

    luaL_checktype(L, 1, LUA_TTABLE);
    a = newpread(L);
    *a = archive_read_new();
    if (*a == NULL)
        return archive_error(L, NULL, "no memory");

    registry_set(L, *a);

    /* store reader callback */
    store_to_fenv(L, "reader");

    /* format & filter */
    setoption(L, *a, "format", ns_rformats, "all");
    setoption(L, *a, "filter", ns_rfilters, "all");

    /* options */
    SET_AR_FIELD(read, options, string);

    if (archive_read_open(*a, L, NULL, callback_read, NULL) != ARCHIVE_OK)
        return archive_error(L, *a, NULL);

    return 1;
}

static int archive_write(lua_State *L)
{
    struct archive **a;

    luaL_checktype(L, 1, LUA_TTABLE);
    a = newpwrite(L);
    *a = archive_write_new();
    if (*a == NULL)
        return archive_error(L, NULL, "no memory");

    registry_set(L, *a);

    store_to_fenv(L, "writer");

    setoption(L, *a, "format", ns_wformats, "raw");
    setoption(L, *a, "filter", ns_wfilters, "none");

    SET_AR_FIELD(write, bytes_per_block, integer);
    SET_AR_FIELD(write, bytes_in_last_block, integer);
    SET_AR_FIELD(write, options, string);

    if (archive_write_open(*a, L, NULL, callback_write, NULL) != ARCHIVE_OK)
        return archive_error(L, *a, NULL);

    return 1;
}

#define DEF_ARCHIVE_FREE(name, callback)                                \
    static int name ## _archive_free(lua_State *L)                      \
    {                                                                   \
        struct archive **a = top ## name(L, 1);                         \
                                                                        \
        if (*a == NULL)                                                 \
            return 0;                                                   \
                                                                        \
        /*                                                              \
         * If called in destructor, we were already removed from        \
         * the weak table, so we need to re-register so that the        \
         * read/write callback will work.                               \
         */                                                             \
        registry_set(L, *a);                                            \
                                                                        \
        if (archive_ ## name ## _close(*a) != ARCHIVE_OK) {             \
            lua_pushfstring(L, "archive_" #name "_close: %s",           \
                            archive_error_string(*a));                  \
            archive_ ## name ## _free(*a);                              \
            lua_error(L);                                               \
            return 0;                                                   \
        }                                                               \
                                                                        \
        /* TODO: needed ? */                                            \
        /* do call once: callback(archive, nil) */                      \
        load_from_fenv(L, 1, #callback);                                \
        if (!lua_isnil(L, -1)) {                                        \
            lua_pushvalue(L, 1);                                        \
            lua_pushnil(L);                                             \
            /* stack: [userdata, callback, userdata, nil] */            \
            lua_call(L, 2, 1);                                          \
        }                                                               \
                                                                        \
        if (archive_ ## name ## _free(*a) != ARCHIVE_OK)                \
            luaL_error(L, "archive_" #name "_free: %s",                 \
                       archive_error_string(*a));                       \
                                                                        \
        *a = NULL;                                                      \
        return 0;                                                       \
    }

DEF_ARCHIVE_FREE(read, reader)
DEF_ARCHIVE_FREE(write, writer)


static int read_archive_next_header(lua_State *L)
{
    struct archive *a = toread(L, 1);
    struct archive_entry **ee;
    int ret;

    ee = newpentry(L);
    *ee = archive_entry_new();
    if (*ee == NULL)
        return archive_error(L, NULL, "no memory");

    ret = archive_read_next_header2(a, *ee);
    if (ret == ARCHIVE_EOF)
        lua_pushnil(L);
    else if (ret != ARCHIVE_OK)
        luaL_error(L, "archive_read_next_header2: %s", archive_error_string(a));

    return 1;
}

static int read_archive_headers(lua_State *L)
{
    struct archive *a = toread(L, 1);
    lua_pushcfunction(L, read_archive_next_header);
    lua_pushvalue(L, 1);
    lua_pushnil(L);
    return 3;
}

static int read_archive_data(lua_State *L)
{
    struct archive *a = toread(L, 1);
    const void *buffer;
    size_t size;
    la_int64_t offset;
    int ret;

    ret = archive_read_data_block(a, &buffer, &size, &offset);
    if (ret == ARCHIVE_EOF)
        return 0;
    else if (ret != ARCHIVE_OK)
        luaL_error(L, "archive_read_data_block: %s", archive_error_string(a));

    lua_pushlstring(L, buffer, size);
    lua_pushnumber(L, offset);
    return 2;
}

static const luaL_Reg read_meth[] = {
    { "next_header", read_archive_next_header },
    { "headers",     read_archive_headers     },
    { "data",        read_archive_data        },
    { "free",        read_archive_free        },
    { "__gc",        read_archive_free        },
    { NULL, NULL }
};

static int write_archive_header(lua_State *L)
{
    struct archive *a = towrite(L, 1);
    struct archive_entry *e = toentry(L, 2);
    const char *pathname;

    pathname = archive_entry_pathname(e);
    if (!pathname || !*pathname)
        luaL_error(L, "invalid entry: 'pathname' field must be set");

    if (archive_write_header(a, e) != ARCHIVE_OK)
        luaL_error(L, "archive_write_header: %s", archive_error_string(a));

    return 0;
}

static int write_archive_data(lua_State *L)
{
    struct archive *a = towrite(L, 1);
    size_t len;
    const char *data = luaL_checklstring(L, 2, &len);
    if (archive_write_data(a, data, len) == -1)
        luaL_error(L, "archive_write_data: %s", archive_error_string(a));
    return 0;
}

static const luaL_Reg write_meth[] = {
    { "header", write_archive_header },
    { "data",   write_archive_data   },
    { "free",   write_archive_free   },
    { "__gc",   write_archive_free   },
    { NULL, NULL }
};

/******************************** archive ********************************/

static int archive_version(lua_State *L)
{
    lua_pushstring(L, archive_version_details());
    return 1;
}

static const luaL_Reg archivelib[] = {
    { "version", archive_version },
    { "read",    archive_read    },
    { "write",   archive_write   },
    { "entry",   archive_entry   },
    { NULL, NULL }
};

LUALIB_API int luaopen_archive(lua_State *L)
{
    luaL_newlib(L, archivelib);

    createmeta(L, METH_ARCHIVE_READ, read_meth);
    createmeta(L, METH_ARCHIVE_WRITE, write_meth);
    createmeta(L, METH_ARCHIVE_ENTRY, entry_meth);

    registry_init(L, METH_ARCHIVE_REGISTRY);

    return 1;
}
