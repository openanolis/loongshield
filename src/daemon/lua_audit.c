/* lua binging for libaudit */

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <compat-5.3.h>

#include "luauxlib.h"

#include <libaudit.h>

#define METH_AUDIT_FD       "meth_audit_fd"
#define METH_AUDIT_RULE     "meth_audit_rule"

struct audit_fd {
    int fd;
};

static struct audit_fd *newafd(lua_State *L)
{
    struct audit_fd *afd = (struct audit_fd *)lua_newuserdata(L, sizeof(*afd));
    afd->fd = -1;
    luaL_getmetatable(L, METH_AUDIT_FD);
    lua_setmetatable(L, -2);
    return afd;
}

#define toafd(L, idx)   \
    ((struct audit_fd *)luaL_checkudata((L), (idx), METH_AUDIT_FD))
#define tofd(L, idx)    (toafd((L), (idx))->fd)


#define newrulp(L) (struct audit_rule_data **)newcptr((L), METH_AUDIT_RULE)
#define torulp(L, idx)  \
    (struct audit_rule_data **)luaL_checkudata((L), (idx), METH_AUDIT_RULE)
#define torule(L, idx)   (*torulp(L, idx))

/******************************** audit_fd ********************************/

static int afd_enabled(lua_State *L)
{
    int auditfd = tofd(L, 1);

    if (lua_gettop(L) == 2) {
        uint32_t enabled = luaL_checkinteger(L, 2);
        int rc = audit_set_enabled(auditfd, enabled);
        lua_pushboolean(L, rc >= 0);
    } else {
        lua_pushboolean(L, audit_is_enabled(auditfd));
    }
    return 1;
}

static int afd_request_status(lua_State *L)
{
    int auditfd = tofd(L, 1);
    lua_pushinteger(L, audit_request_status(auditfd));
    return 1;
}

static int afd_request_features(lua_State *L)
{
    int auditfd = tofd(L, 1);
    lua_pushinteger(L, audit_request_features(auditfd));
    return 1;
}

static int afd_set_pid(lua_State *L)
{
    int auditfd = tofd(L, 1);
    uint32_t pid = luaL_checkinteger(L, 2);
    rep_wait_t wmode = lua_toboolean(L, 3);
    int rc = audit_set_pid(auditfd, pid, wmode);
    lua_pushboolean(L, rc >= 0);
    return 1;
}

static int afd_set_feature(lua_State *L)
{
    int auditfd = tofd(L, 1);
    unsigned int feature = luaL_checkinteger(L, 2);
    unsigned int value = luaL_checkinteger(L, 3);
    unsigned int lock = luaL_checkinteger(L, 4);
    int rc = audit_set_feature(auditfd, feature, value, lock);
    lua_pushboolean(L, rc >= 0);
    return 1;
}

#define AFD_SET_METHOD(name)                        \
    static int afd_set_ ## name(lua_State *L)       \
    {                                               \
        int auditfd = tofd(L, 1);                   \
        uint32_t v = luaL_checkinteger(L, 2);       \
        int rc = audit_set_ ## name(auditfd, v);    \
        lua_pushboolean(L, rc >= 0);                \
        return 1;                                   \
    }

AFD_SET_METHOD(failure)
AFD_SET_METHOD(rate_limit)
AFD_SET_METHOD(backlog_limit)
AFD_SET_METHOD(backlog_wait_time)

#define AFD_OP0_METHOD(name)                        \
    static int afd_ ## name(lua_State *L)           \
    {                                               \
        int auditfd = tofd(L, 1);                   \
        int rc = audit_ ## name(auditfd);           \
        lua_pushboolean(L, rc >= 0);                \
        return 1;                                   \
    }

AFD_OP0_METHOD(reset_lost)
AFD_OP0_METHOD(reset_backlog_wait_time_actual)
AFD_OP0_METHOD(set_loginuid_immutable)
AFD_OP0_METHOD(trim_subtrees)

static int afd_make_equivalent(lua_State *L)
{
    int auditfd = tofd(L, 1);
    const char *mount_point = luaL_checkstring(L, 2);
    const char *subtree = luaL_checkstring(L, 3);
    int rc = audit_make_equivalent(auditfd, mount_point, subtree);
    lua_pushboolean(L, rc >= 0);
    return 1;
}

#define AFD_RULE_OP(name)                                               \
    static int afd_ ## name(lua_State *L)                               \
    {                                                                   \
        int auditfd = tofd(L, 1);                                       \
        struct audit_rule_data *rule = torule(L, 2);                    \
        int flags = luaL_checkinteger(L, 3);                            \
        int action = luaL_checkinteger(L, 4);                           \
        int rc = audit_ ## name ## _data(auditfd, rule, flags, action); \
        lua_pushboolean(L, rc >= 0);                                    \
        return 1;                                                       \
    }

AFD_RULE_OP(add_rule)
AFD_RULE_OP(delete_rule)


#define GET_FIELD(L, idx, name, type)               \
    lua_getfield((L), (idx), # name);               \
    name = luaL_check ## type((L), -1);

static int log_user_message(lua_State *L)
{
    int auditfd = tofd(L, 1);
    const char *message, *hostname, *addr, *tty;
    int type, result;
    int rc;

    luaL_checktype(L, 2, LUA_TTABLE);

    GET_FIELD(L, 2, type,     integer);
    GET_FIELD(L, 2, message,  string);
    GET_FIELD(L, 2, hostname, string);
    GET_FIELD(L, 2, addr,     string);
    GET_FIELD(L, 2, tty,      string);

    if (lua_getfield(L, 2, "comm"), lua_isstring(L, -1)) {
        const char *comm = lua_tostring(L, -1);

        GET_FIELD(L, 2, result, integer);
        rc = audit_log_user_comm_message(auditfd, type, message, comm,
                                         hostname, addr, tty, result);
    } else if (lua_getfield(L, 2, "uid"), lua_isinteger(L, -1)) {
        uid_t uid = lua_tointeger(L, -1);

        rc = audit_log_user_avc_message(auditfd, type, message,
                                        hostname, addr, tty, uid);
    } else {
        GET_FIELD(L, 2, result, integer);
        rc = audit_log_user_message(auditfd, type, message,
                                    hostname, addr, tty, result);
    }

    lua_pushboolean(L, rc >= 0);
    return 1;
}

static int log_acct_message(lua_State *L)
{
    int auditfd = tofd(L, 1);
    const char *pgname, *op, *name, *host, *addr, *tty;
    int type, result;
    unsigned int id;
    int rc;

    luaL_checktype(L, 2, LUA_TTABLE);

    GET_FIELD(L, 2, type,   integer);
    GET_FIELD(L, 2, result, integer);
    GET_FIELD(L, 2, id,     integer);
    GET_FIELD(L, 2, pgname, string);
    GET_FIELD(L, 2, op,     string);
    GET_FIELD(L, 2, name,   string);
    GET_FIELD(L, 2, host,   string);
    GET_FIELD(L, 2, addr,   string);
    GET_FIELD(L, 2, tty,    string);

    rc = audit_log_acct_message(auditfd, type, pgname, op, name, id,
                                host, addr, tty, result);

    lua_pushboolean(L, rc >= 0);
    return 1;
}

static int log_semanage_message(lua_State *L)
{
    int auditfd = tofd(L, 1);
    const char *pgname, *op, *name, *host, *addr, *tty;
    const char *new_seuser, *new_role, *new_range;
    const char *old_seuser, *old_role, *old_range;
    int type, result;
    unsigned int id;
    int rc;

    luaL_checktype(L, 2, LUA_TTABLE);

    GET_FIELD(L, 2, type,       integer);
    GET_FIELD(L, 2, result,     integer);
    GET_FIELD(L, 2, id,         integer);
    GET_FIELD(L, 2, pgname,     string);
    GET_FIELD(L, 2, op,         string);
    GET_FIELD(L, 2, name,       string);
    GET_FIELD(L, 2, host,       string);
    GET_FIELD(L, 2, addr,       string);
    GET_FIELD(L, 2, tty,        string);
    GET_FIELD(L, 2, new_seuser, string);
    GET_FIELD(L, 2, new_role,   string);
    GET_FIELD(L, 2, new_range,  string);
    GET_FIELD(L, 2, old_seuser, string);
    GET_FIELD(L, 2, old_role,   string);
    GET_FIELD(L, 2, old_range,  string);

    rc = audit_log_semanage_message(auditfd, type, pgname, op, name, id,
                                    new_seuser, new_role, new_range,
                                    old_seuser, old_role, old_range,
                                    host, addr, tty, result);

    lua_pushboolean(L, rc >= 0);
    return 1;
}

static int log_user_command(lua_State *L)
{
    int auditfd = tofd(L, 1);
    const char *command, *tty;
    int type, result;
    int rc;

    luaL_checktype(L, 2, LUA_TTABLE);

    GET_FIELD(L, 2, type,    integer);
    GET_FIELD(L, 2, result,  integer);
    GET_FIELD(L, 2, command, string);
    GET_FIELD(L, 2, tty,     string);

    rc = audit_log_user_command(auditfd, type, command, tty, result);

    lua_pushboolean(L, rc >= 0);
    return 1;
}

static int auditfd_free(lua_State *L)
{
    struct audit_fd *afd = toafd(L, 1);
    if (afd->fd != -1) {
        audit_close(afd->fd);
        afd->fd = -1;
    }
    return 0;
}

static const luaL_Reg auditfd_meth[] = {
    { "enabled",                afd_enabled                 },
    { "request_status",         afd_request_status          },
    { "request_features",       afd_request_features        },
    { "set_pid",                afd_set_pid                 },
    { "set_feature",            afd_set_feature             },
    { "set_failure",            afd_set_failure             },
    { "set_rate_limit",         afd_set_rate_limit          },
    { "set_backlog_limit",      afd_set_backlog_limit       },
    { "set_backlog_wait_time",  afd_set_backlog_wait_time   },
    { "reset_lost",             afd_reset_lost              },
    { "reset_backlog_wait_time_actual", afd_reset_backlog_wait_time_actual },
    { "set_loginuid_immutable", afd_set_loginuid_immutable  },
    { "trim_subtrees",          afd_trim_subtrees           },
    { "make_equivalent",        afd_make_equivalent         },
    { "add_rule",               afd_add_rule                },
    { "delete_rule",            afd_delete_rule             },
    { "log_user_message",       log_user_message            },
    { "log_acct_message",       log_acct_message            },
    { "log_semanage_message",   log_semanage_message        },
    { "log_user_command",       log_user_command            },
    { "close",                  auditfd_free                },
    { "__gc",                   auditfd_free                },
    { NULL, NULL }
};

/******************************** rule ********************************/

static int rule_syscallbyname(lua_State *L)
{
    struct audit_rule_data *rule = torule(L, 1);
    const char *scall = luaL_checkstring(L, 2);
    int rc = audit_rule_syscallbyname_data(rule, scall);
    lua_pushboolean(L, rc >= 0);
    return 1;
}

/* Not compatible with older versions
static int rule_iouringbyname(lua_State *L)
{
    struct audit_rule_data *rule = torule(L, 1);
    const char *scall = luaL_checkstring(L, 2);
    int rc = audit_rule_io_uringbyname_data(rule, scall);
    lua_pushboolean(L, rc >= 0);
    return 1;
}
*/

static int rule_fieldpair(lua_State *L)
{
    struct audit_rule_data **rulp = torulp(L, 1);
    const char *pair = luaL_checkstring(L, 2);
    int flags = luaL_checkinteger(L, 3);
    int rc = audit_rule_fieldpair_data(rulp, pair, flags);
    lua_pushboolean(L, rc >= 0);
    return 1;
}

static int rule_interfield_comp(lua_State *L)
{
    struct audit_rule_data **rulp = torulp(L, 1);
    const char *pair = luaL_checkstring(L, 2);
    int flags = luaL_checkinteger(L, 3);
    int rc = audit_rule_interfield_comp_data(rulp, pair, flags);
    lua_pushboolean(L, rc >= 0);
    return 1;
}

static int rule_update_watch_perms(lua_State *L)
{
    struct audit_rule_data *rule = torule(L, 1);
    int perms = luaL_checkinteger(L, 2);
    int rc = audit_update_watch_perms(rule, perms);
    lua_pushboolean(L, rc >= 0);
    return 1;
}

static int rule_add_watch(lua_State *L)
{
    struct audit_rule_data **rulp = torulp(L, 1);
    const char *path = luaL_checkstring(L, 2);
    int rc = audit_add_watch(rulp, path);
    lua_pushboolean(L, rc >= 0);
    return 1;
}

static int rule_add_watch_dir(lua_State *L)
{
    struct audit_rule_data **rulp = torulp(L, 1);
    const char *path = luaL_checkstring(L, 2);
    int type = luaL_checkinteger(L, 3);
    int rc = audit_add_watch_dir(type, rulp, path);
    lua_pushboolean(L, rc >= 0);
    return 1;
}

static int rule_free(lua_State *L)
{
    struct audit_rule_data **rulp = torulp(L, 1);
    if (*rulp) {
        audit_rule_free_data(*rulp);
        *rulp = NULL;
    }
    return 0;
}

static const luaL_Reg rule_meth[] = {
    { "syscallbyname",      rule_syscallbyname      },
    /*
    { "iouringbyname",      rule_iouringbyname      },
    */
    { "fieldpair",          rule_fieldpair          },
    { "interfield_comp",    rule_interfield_comp    },
    { "update_watch_perms", rule_update_watch_perms },
    { "add_watch",          rule_add_watch          },
    { "add_watch_dir",      rule_add_watch_dir      },
    { "close",              rule_free               },
    { "__gc",               rule_free               },
    { NULL, NULL }
};

/******************************** audit ********************************/

static int l_open(lua_State *L)
{
    struct audit_fd *afd = newafd(L);
    afd->fd = audit_open();
    if (afd->fd == -1)
        return 0;
    return 1;
}

static int l_rule_create(lua_State *L)
{
    struct audit_rule_data **rulp = newrulp(L);

    *rulp = audit_rule_create_data();
    if (*rulp == NULL)
        return 0;

    audit_rule_init_data(*rulp);
    return 1;
}

static int l_features(lua_State *L)
{
    uint32_t features = audit_get_features();
    lua_pushinteger(L, features);
    return 1;
}

static int l_loginuid(lua_State *L)
{
    if (lua_gettop(L) == 1) {
        uid_t uid = luaL_checkinteger(L, 1);
        int rc = audit_setloginuid(uid);
        lua_pushboolean(L, rc >= 0);
    } else {
        lua_pushinteger(L, audit_getloginuid());
    }
    return 1;
}

static int l_can_control(lua_State *L)
{
    lua_pushboolean(L, audit_can_control());
    return 1;
}

static int l_can_write(lua_State *L)
{
    lua_pushboolean(L, audit_can_write());
    return 1;
}

static int l_can_read(lua_State *L)
{
    lua_pushboolean(L, audit_can_read());
    return 1;
}

static const luaL_Reg auditlib[] = {
    { "open",        l_open        },
    { "rule_create", l_rule_create },
    { "features",    l_features    },
    { "loginuid",    l_loginuid    },
    { "can_control", l_can_control },
    { "can_write",   l_can_write   },
    { "can_read",    l_can_read    },
    { NULL, NULL }
};

LUALIB_API int luaopen_audit(lua_State *L)
{
    luaL_newlib(L, auditlib);

    createmeta(L, METH_AUDIT_FD, auditfd_meth);
    createmeta(L, METH_AUDIT_RULE, rule_meth);

    return 1;
}
