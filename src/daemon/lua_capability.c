
#include <errno.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <compat-5.3.h>

#include "luauxlib.h"

#include <sys/capability.h>

#define METH_CAP_CAP            "meth_cap_cap"
#define METH_CAP_IAB            "meth_cap_iab"

#define newcapcap(L)    (cap_t *)newcptr((L), METH_CAP_CAP)
#define newcapiab(L)    (cap_iab_t *)newcptr((L), METH_CAP_IAB)

#define tocapcapp(L, idx) (cap_t *)luaL_checkudata((L), (idx), METH_CAP_CAP)
#define tocapiabp(L, idx) (cap_iab_t *)luaL_checkudata((L), (idx), METH_CAP_IAB)

#define tocapcap(L, idx)  (*tocapcapp(L, idx))
#define tocapiab(L, idx)  (*tocapiabp(L, idx))


static int cap_result(lua_State *L, int err)
{
    if (err == 0) {
        lua_pushboolean(L, 1);
        return 1;
    } else if (err == -1) {
        lua_pushnil(L);
        lua_pushinteger(L, errno);
        return 2;
    } else {
        lua_pushnil(L);
        lua_pushinteger(L, err);
        return 2;
    }
}

/*********************************** cap ***********************************/

static int lcap_free(lua_State *L)
{
    cap_t *capp = tocapcapp(L, 1);
    if (*capp) {
        cap_free(*capp);
        *capp = NULL;
    }
    return 0;
}

static int lcap_tostring(lua_State *L)
{
    cap_t cap = tocapcap(L, 1);
    ssize_t len;
    char *s = cap_to_text(cap, &len);
    if (s == NULL)
        return 0;
    lua_pushlstring(L, s, len);
    cap_free(s);
    return 1;
}

static int lcap_compare(lua_State *L)
{
    cap_t cap1 = tocapcap(L, 1);
    cap_t cap2 = tocapcap(L, 2);
    int r = cap_compare(cap1, cap2);
    lua_pushboolean(L, r == 0);
    return 1;
}

static const struct cflag_opt cap_set_opts[] = {
    { "effective",   CAP_EFFECTIVE   },
    { "permitted",   CAP_PERMITTED   },
    { "inheritable", CAP_INHERITABLE },
    { NULL, 0 },
};

/*
 * get:
 *   cap:flag('effective', 'cap_chown')
 * set:
 *   cap:flag('effective', true, 'cap_chown', 'cap_bpf', ...)
 *   cap:flag('effective', true, { 'cap_chown', 'cap_bpf', ... })
 */
static int lcap_flag(lua_State *L)
{
    cap_t cap = tocapcap(L, 1);
    cap_flag_t set = tocflags(L, 2, cap_set_opts, CAP_EFFECTIVE);
    int top = lua_gettop(L);
    const char *name;
    cap_value_t v;
    cap_flag_value_t raise;
    int err;

    if (top < 3)
        return cap_result(L, ENODEV);

    if (top == 3) {
        name = luaL_checkstring(L, 3);
        err = cap_from_name(name, &v);
        if (err < 0)
            return cap_result(L, err);

        err = cap_get_flag(cap, v, set, &raise);
        if (err < 0)
            return cap_result(L, err);
        switch (raise) {
        case CAP_CLEAR: lua_pushboolean(L, 0); break;
        case CAP_SET:   lua_pushboolean(L, 1); break;
        }
        return 1;
    } else {
        int b = lua_toboolean(L, 3);
        cap_value_t values[64];
        int idx, k, n = 0;

        for (idx = 4; idx <= top; idx++) {
            switch (lua_type(L, idx)) {
            case LUA_TSTRING:
                name = luaL_checkstring(L, idx);
                err = cap_from_name(name, &v);
                if (err < 0)
                    break;
                values[n++] = v;
                if (n >= 64)
                    goto _set;
                break;
            case LUA_TTABLE:
                for (k = 1; lua_rawgeti(L, idx, k), !lua_isnil(L, -1);
                     lua_pop(L, 1)) {
                    name = luaL_checkstring(L, -1);
                    err = cap_from_name(name, &v);
                    if (err < 0)
                        continue;
                    values[n++] = v;
                    if (n >= 64)
                        goto _set;
                }
                break;
            default:
                break;
            }
        }
_set:
        raise = b ? CAP_SET : CAP_CLEAR;
        err = cap_set_flag(cap, set, n, values, raise);
        return cap_result(L, err);
    }
}

static int lcap_clear(lua_State *L)
{
    cap_t cap = tocapcap(L, 1);
    int err;
    if (lua_gettop(L) == 1) {
        err = cap_clear(cap);
    } else {
        cap_flag_t set = tocflags(L, 2, cap_set_opts, CAP_EFFECTIVE);
        err = cap_clear_flag(cap, set);
    }
    return cap_result(L, err);
}

/*
 * cap:fill()                   # pP -> pE
 * cap:fill(to, from)           # p(from) -> p(to)
 * cap:fill(to, from, capfrom)  # capfrom(from) -> p(to)
 */
static int lcap_fill(lua_State *L)
{
    cap_t cap = tocapcap(L, 1);
    cap_flag_t to = tocflags(L, 2, cap_set_opts, CAP_EFFECTIVE);
    cap_flag_t from = tocflags(L, 3, cap_set_opts, CAP_PERMITTED);
    cap_t capfrom;
    int top = lua_gettop(L);
    int err;
    switch (top) {
    case 1:
    case 3:
        err = cap_fill(cap, to, from);
        break;
    case 4:
        capfrom = tocapcap(L, 4);
        err = cap_fill_flag(cap, to, capfrom, from);
        break;
    default:
        err = EINVAL;
        break;
    }
    return cap_result(L, err);
}

static int lcap_nsowner(lua_State *L)
{
    cap_t cap = tocapcap(L, 1);
    if (lua_gettop(L) == 1) {
        lua_pushinteger(L, cap_get_nsowner(cap));
        return 1;
    } else {
        uid_t uid = luaL_checkinteger(L, 2);
        int err = cap_set_nsowner(cap, uid);
        return cap_result(L, err);
    }
}

static int lcap_set_fd(lua_State *L)
{
    cap_t cap = tocapcap(L, 1);
    int fd = luaL_checkinteger(L, 2);
    int err = cap_set_fd(fd, cap);
    return cap_result(L, err);
}

static int lcap_set_file(lua_State *L)
{
    cap_t cap = tocapcap(L, 1);
    const char *file = luaL_checkstring(L, 2);
    int err = cap_set_file(file, cap);
    return cap_result(L, err);
}

static int lcap_set_proc(lua_State *L)
{
    cap_t cap = tocapcap(L, 1);
    int err = cap_set_proc(cap);
    return cap_result(L, err);
}

static const luaL_Reg cap_meth[] = {
    { "free",           lcap_free           },
    { "__gc",           lcap_free           },
    { "__tostring",     lcap_tostring       },
    { "__eq",           lcap_compare        },
    { "flag",           lcap_flag           },
    { "clear",          lcap_clear          },
    { "fill",           lcap_fill           },
    { "nsowner",        lcap_nsowner        },
    { "set_fd",         lcap_set_fd         },
    { "set_file",       lcap_set_file       },
    { "set_proc",       lcap_set_proc       },
    { NULL, NULL }
};

/*********************************** iab ***********************************/

static int liab_free(lua_State *L)
{
    cap_iab_t *iabp = tocapiabp(L, 1);
    if (*iabp) {
        cap_free(*iabp);
        *iabp = NULL;
    }
    return 0;
}

static int liab_tostring(lua_State *L)
{
    cap_iab_t iab = tocapiab(L, 1);
    char *s = cap_iab_to_text(iab);
    lua_pushstring(L, s);
    cap_free(s);
    return 1;
}

static int liab_compare(lua_State *L)
{
    cap_iab_t iab1 = tocapiab(L, 1);
    cap_iab_t iab2 = tocapiab(L, 2);
    int r = cap_iab_compare(iab1, iab2);
    lua_pushboolean(L, r == 0);
    return 1;
}

static const struct cflag_opt cap_iab_opts[] = {
    { "inheritable",    CAP_IAB_INH    },
    { "ambient",        CAP_IAB_AMB    },
    { "bound",          CAP_IAB_BOUND  },
    { NULL, 0 },
};

/*
 * get:
 *   iab:vector('inheritable', 'cap_chown')
 * set:
 *   iab:vector('ambient', 'cap_bpf', true)
 */
static int liab_vector(lua_State *L)
{
    cap_iab_t iab = tocapiab(L, 1);
    cap_iab_vector_t vector = tocflags(L, 2, cap_iab_opts, CAP_IAB_INH);
    const char *name = luaL_checkstring(L, 3);
    cap_value_t v;
    cap_flag_value_t raise;
    int err;

    err = cap_from_name(name, &v);
    if (err < 0)
        return cap_result(L, err);

    if (lua_gettop(L) == 3) {
        raise = cap_iab_get_vector(iab, vector, v);
        switch (raise) {
        case CAP_CLEAR: lua_pushboolean(L, 0); break;
        case CAP_SET:   lua_pushboolean(L, 1); break;
        }
        return 1;
    } else {
        int b = lua_toboolean(L, 4);
        raise = b ? CAP_SET : CAP_CLEAR;
        err = cap_iab_set_vector(iab, vector, v, raise);
        return cap_result(L, err);
    }
}

static int liab_fill(lua_State *L)
{
    cap_iab_t iab = tocapiab(L, 1);
    cap_iab_vector_t vector = tocflags(L, 2, cap_iab_opts, CAP_IAB_INH);
    cap_t cap = tocapcap(L, 3);
    cap_flag_t set = tocflags(L, 4, cap_set_opts, CAP_EFFECTIVE);
    int err = cap_iab_fill(iab, vector, cap, set);
    return cap_result(L, err);
}

static int liab_set_proc(lua_State *L)
{
    cap_iab_t iab = tocapiab(L, 1);
    int err = cap_iab_set_proc(iab);
    return cap_result(L, err);
}

static const luaL_Reg iab_meth[] = {
    { "free",           liab_free           },
    { "__gc",           liab_free           },
    { "__tostring",     liab_tostring       },
    { "__eq",           liab_compare        },
    { "vector",         liab_vector         },
    { "fill",           liab_fill           },
    { "set_proc",       liab_set_proc       },
    { NULL, NULL }
};

/*********************************** cap ***********************************/

static int lcap_init(lua_State *L)
{
    cap_t *capp = newcapcap(L);
    *capp = cap_init();
    if (*capp == NULL)
        lua_pushnil(L);
    return 1;
}

static int lcap_get_fd(lua_State *L)
{
    int fd = luaL_checkinteger(L, 1);
    cap_t *capp = newcapcap(L);
    *capp = cap_get_fd(fd);
    if (*capp == NULL)
        lua_pushnil(L);
    return 1;
}

static int lcap_get_file(lua_State *L)
{
    const char *file = luaL_checkstring(L, 1);
    cap_t *capp = newcapcap(L);
    *capp = cap_get_file(file);
    if (*capp == NULL)
        lua_pushnil(L);
    return 1;
}

static int lcap_get_proc(lua_State *L)
{
    cap_t *capp = newcapcap(L);
    *capp = cap_get_proc();
    if (*capp == NULL)
        lua_pushnil(L);
    return 1;
}

static int lcap_get_pid(lua_State *L)
{
    pid_t pid = (pid_t)luaL_checkinteger(L, 1);
    cap_t *capp = newcapcap(L);
    *capp = cap_get_pid(pid);
    if (*capp == NULL)
        lua_pushnil(L);
    return 1;
}

static int lcap_from_text(lua_State *L)
{
    const char *text = luaL_checkstring(L, 1);
    cap_t *capp = newcapcap(L);
    *capp = cap_from_text(text);
    if (*capp == NULL)
        lua_pushnil(L);
    return 1;
}

static int lcap_iab_init(lua_State *L)
{
    cap_iab_t *iabp = newcapiab(L);
    *iabp = cap_iab_init();
    if (*iabp == NULL)
        lua_pushnil(L);
    return 1;
}

static int lcap_iab_from_text(lua_State *L)
{
    const char *text = luaL_checkstring(L, 1);
    cap_iab_t *iabp = newcapiab(L);
    *iabp = cap_iab_from_text(text);
    if (*iabp == NULL)
        lua_pushnil(L);
    return 1;
}

static int lcap_iab_get_proc(lua_State *L)
{
    cap_iab_t *iabp = newcapiab(L);
    *iabp = cap_iab_get_proc();
    if (*iabp == NULL)
        lua_pushnil(L);
    return 1;
}

static int lcap_iab_get_pid(lua_State *L)
{
    pid_t pid = (pid_t)luaL_checkinteger(L, 1);
    cap_iab_t *iabp = newcapiab(L);
    *iabp = cap_iab_get_pid(pid);
    if (*iabp == NULL)
        lua_pushnil(L);
    return 1;
}

static int lcap_from_name(lua_State *L)
{
    const char *name = luaL_checkstring(L, 1);
    cap_value_t v;
    int err = cap_from_name(name, &v);
    if (err)
        return 0;
    lua_pushinteger(L, v);
    return 1;
}

static int lcap_to_name(lua_State *L)
{
    cap_value_t v = luaL_checkinteger(L, 1);
    char *name = cap_to_name(v);
    if (name == NULL)
        return 0;
    lua_pushstring(L, name);
    cap_free(name);
    return 1;
}

static int lcap_max_bits(lua_State *L)
{
    lua_pushinteger(L, cap_max_bits());
    return 1;
}

static int lcap_bound(lua_State *L, int drop)
{
    const char *name = luaL_checkstring(L, 1);
    cap_value_t v;
    int err;

    err = cap_from_name(name, &v);
    if (err < 0)
        return cap_result(L, err);

    if (drop)
        err = cap_drop_bound(v);
    else
        err = cap_get_bound(v);

    return cap_result(L, err);
}

static int lcap_get_bound(lua_State *L)
{
    return lcap_bound(L, 0);
}

static int lcap_drop_bound(lua_State *L)
{
    return lcap_bound(L, 1);
}

/*
 * get:
 *   cap.ambient('cap_bpf')
 * set:
 *   cap.ambient('cap_bpf', true)
 *   cap.ambient('cap_bpf', false)
 */
static int lcap_ambient(lua_State *L)
{
    const char *name = luaL_checkstring(L, 1);
    cap_value_t v;
    int err;

    err = cap_from_name(name, &v);
    if (err < 0)
        return cap_result(L, err);

    if (lua_gettop(L) == 2) {
        int b = lua_toboolean(L, 2);
        err = cap_set_ambient(v, b ? CAP_SET : CAP_CLEAR);
    } else {
        err = cap_get_ambient(v);
    }
    return cap_result(L, err);
}

static int lcap_reset_ambient(lua_State *L)
{
    int err = cap_reset_ambient();
    return cap_result(L, err);
}

static int lcap_mode(lua_State *L)
{
    static const struct cflag_opt mode_opts[] = {
        { "uncertain",   CAP_MODE_UNCERTAIN   },
        { "nopriv",      CAP_MODE_NOPRIV      },
        { "pure1e_init", CAP_MODE_PURE1E_INIT },
        { "pure1e",      CAP_MODE_PURE1E      },
        { "hybrid",      CAP_MODE_HYBRID      },
        { NULL, 0 },
    };
    cap_mode_t mode;
    int err;
    if (lua_gettop(L) >= 1) {
        mode = tocflags(L, 1, mode_opts, CAP_MODE_UNCERTAIN);
        err = cap_set_mode(mode);
        return cap_result(L, err);
    } else {
        mode = cap_get_mode();
        lua_pushstring(L, fromcflags(mode_opts, mode, "unknown"));
        return 1;
    }
}

static int lcap_secbits(lua_State *L)
{
    if (lua_gettop(L) >= 1) {
        unsigned int secbits = luaL_checkinteger(L, 1);
        int err = cap_set_secbits(secbits);
        return cap_result(L, err);
    } else {
        lua_pushinteger(L, cap_get_secbits());
        return 1;
    }
}

static int lcap_setuid(lua_State *L)
{
    uid_t uid = luaL_checkinteger(L, 1);
    int err = cap_setuid(uid);
    return cap_result(L, err);
}

static int lcap_setgroups(lua_State *L)
{
    gid_t gid = luaL_checkinteger(L, 1);
    gid_t groups[64];
    int k, n = 0;
    int err;
    if (lua_type(L, 2) == LUA_TTABLE) {
        for (k = 1; lua_rawgeti(L, 2, k), !lua_isnil(L, -1); lua_pop(L, 1)) {
            gid_t id = luaL_checkinteger(L, -1);
            groups[n++] = id;
            if (n >= 64)
                break;
        }
    } else {
        int top = lua_gettop(L);
        for (k = 2; k <= top; k++) {
            gid_t id = luaL_checkinteger(L, k);
            groups[n++] = id;
            if (n >= 64)
                break;
        }
    }
    err = cap_setgroups(gid, n, groups);
    return cap_result(L, err);
}

static const luaL_Reg caplib[] = {
    { "init",           lcap_init           },
    { "get_fd",         lcap_get_fd         },
    { "get_file",       lcap_get_file       },
    { "get_proc",       lcap_get_proc       },
    { "get_pid",        lcap_get_pid        },
    { "from_text",      lcap_from_text      },
    { "iab_init",       lcap_iab_init       },
    { "iab_from_text",  lcap_iab_from_text  },
    { "iab_get_proc",   lcap_iab_get_proc   },
    { "iab_get_pid",    lcap_iab_get_pid    },
    { "from_name",      lcap_from_name      },
    { "to_name",        lcap_to_name        },
    { "max_bits",       lcap_max_bits       },
    { "get_bound",      lcap_get_bound      },
    { "drop_bound",     lcap_drop_bound     },
    { "ambient",        lcap_ambient        },
    { "reset_ambient",  lcap_reset_ambient  },
    { "mode",           lcap_mode           },
    { "secbits",        lcap_secbits        },
    { "setuid",         lcap_setuid         },
    { "setgroups",      lcap_setgroups      },
    { NULL, NULL }
};

LUALIB_API int luaopen_capability(lua_State *L)
{
    luaL_newlib(L, caplib);

    createmeta(L, METH_CAP_CAP, cap_meth);
    createmeta(L, METH_CAP_IAB, iab_meth);

    return 1;
}
