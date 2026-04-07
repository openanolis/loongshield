#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <compat-5.3.h>

#include "luauxlib.h"

#include <systemd/sd-daemon.h>
#include <systemd/sd-bus.h>


#define METH_SYSTEMD_BUS                "meth_systemd_bus"
#define METH_SYSTEMD_MESSAGE            "meth_systemd_message"


#define newbus(L)       (sd_bus **)newcptr((L), METH_SYSTEMD_BUS)
#define newmessage(L)   (sd_bus_message **)newcptr((L), METH_SYSTEMD_MESSAGE)

#define tobus(L, idx)       \
    (*(sd_bus **)luaL_checkudata((L), (idx), METH_SYSTEMD_BUS))
#define tomessage(L, idx)   \
    (*(sd_bus_message **)luaL_checkudata((L), (idx), METH_SYSTEMD_MESSAGE))


/******************************** message ********************************/

static int message_append(lua_State *L)
{
    sd_bus_message *m = tomessage(L, 1);
    int n = lua_gettop(L);
    int idx;

    for (idx = 2; idx <= n; idx++) {
        const char *s;
        uint32_t num;
        int err;

        switch (lua_type(L, idx)) {
        case LUA_TSTRING:
            s = lua_tostring(L, idx);
            err = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, s);
            break;

        case LUA_TNUMBER:
            num = (uint32_t)lua_tointeger(L, idx);
            err = sd_bus_message_append_basic(m, SD_BUS_TYPE_UINT32, &num);
            break;

        default:
            err = -EINVAL;
            break;
        }

        if (err < 0) {
            lua_pushnil(L);
            lua_pushinteger(L, -err);
            return 2;
        }
    }
    lua_settop(L, 1);
    return 1;
}

static int message_read_basic(lua_State *L)
{
    sd_bus_message *m = tomessage(L, 1);
    char type = (char)luaL_checkinteger(L, 2);
    void *p = NULL;
    int err;

    err = sd_bus_message_read_basic(m, type, (void *)&p);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }

    switch (type) {
    case SD_BUS_TYPE_STRING:
        lua_pushstring(L, (const char *)p);
        break;

    case SD_BUS_TYPE_UINT32:
        lua_pushinteger(L, (lua_Integer)(uint32_t)(uintptr_t)p);
        break;

    default:
        lua_pushnil(L);
        break;
    }
    return 1;
}

static int message_read(lua_State *L)
{
    sd_bus_message *m = tomessage(L, 1);
    const char *types = luaL_checkstring(L, 2);
    const char *t;
    void *p = NULL;
    int err;
    int nres = 0;

    for (t = types; *t; t++) {
        err = sd_bus_message_read_basic(m, *t, (void *)&p);
        if (err < 0) {
            lua_pushnil(L);
            lua_pushinteger(L, -err);
            return 2;
        }

        switch (*t) {
        case SD_BUS_TYPE_BOOLEAN:
            lua_pushboolean(L, (int)(intptr_t)p);
            break;

        case SD_BUS_TYPE_INT16:
            lua_pushinteger(L, (lua_Integer)(int16_t)(intptr_t)p);
            break;

        case SD_BUS_TYPE_UINT16:
            lua_pushinteger(L, (lua_Integer)(uint16_t)(uintptr_t)p);
            break;

        case SD_BUS_TYPE_INT32:
            lua_pushinteger(L, (lua_Integer)(int32_t)(intptr_t)p);
            break;

        case SD_BUS_TYPE_UINT32:
            lua_pushinteger(L, (lua_Integer)(uint32_t)(uintptr_t)p);
            break;

        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_OBJECT_PATH:
            lua_pushstring(L, (const char *)p);
            break;

        default:
            lua_pushnil(L);
            break;
        }
        nres++;
    }
    return nres;
}

static int do_message_decode(lua_State *L, sd_bus_message *m, int idx)
{
    while (1) {
        char type;
        const char *types = NULL;
        void *p = NULL;
        int err;

        err = sd_bus_message_peek_type(m, &type, &types);
        if (err <= 0)
            return err;

        err = sd_bus_message_read_basic(m, type, (void *)&p);
        if (err < 0)
            return err;

        switch (type) {
        case SD_BUS_TYPE_UINT32:
            lua_pushinteger(L, (lua_Integer)(uint32_t)(uintptr_t)p);
            lua_rawseti(L, -2, idx++);
            break;

        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_OBJECT_PATH:
            lua_pushstring(L, (const char *)p);
            lua_rawseti(L, -2, idx++);
            break;

        case SD_BUS_TYPE_ARRAY:
            err = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, types);
            if (err <= 0)
                return err;

            lua_newtable(L);
            err = do_message_decode(L, m, 1);
            if (err < 0)
                return err;

            lua_rawseti(L, -2, idx++);
            err = sd_bus_message_exit_container(m);
            if (err < 0)
                return err;
            break;


        case SD_BUS_TYPE_STRUCT_BEGIN:
        case SD_BUS_TYPE_DICT_ENTRY_BEGIN:
        case SD_BUS_TYPE_STRUCT_END:
        case SD_BUS_TYPE_DICT_ENTRY_END:
            /* TODO */
            return -EDOM;

        default:
            return -EDOM;
        }
    }
}

static int message_decode(lua_State *L)
{
    sd_bus_message *m = tomessage(L, 1);
    int err;
    lua_newtable(L);
    err = do_message_decode(L, m, 1);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    return 1;
}

static int message_peek_type(lua_State *L)
{
    sd_bus_message *m = tomessage(L, 1);
    char type;
    const char *types = NULL;
    int err;

    err = sd_bus_message_peek_type(m, &type, &types);
    if (err <= 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
    } else {
        lua_pushinteger(L, (lua_Integer)type);
        lua_pushstring(L, types);
    }
    return 2;
}

static int message_rewind(lua_State *L)
{
    sd_bus_message *m = tomessage(L, 1);
    int complete = lua_toboolean(L, 2);
    int err = sd_bus_message_rewind(m, complete);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

/*
static int message_dump(lua_State *L)
{
    sd_bus_message *m = tomessage(L, 1);
    int err = sd_bus_message_dump(m, NULL, SD_BUS_MESSAGE_DUMP_WITH_HEADER);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}
*/

static int message_unref(lua_State *L)
{
    sd_bus_message *m = tomessage(L, 1);
    sd_bus_message_unref(m);
    return 0;
}

static const luaL_Reg message_meth[] = {
    { "append",       message_append       },
    { "read_basic",   message_read_basic   },
    { "read",         message_read         },
    { "decode",       message_decode       },
    { "peek_type",    message_peek_type    },
    { "rewind",       message_rewind       },
    /*{ "dump",         message_dump         },*/
    { "__gc",         message_unref        },
    { NULL, NULL }
};

/******************************** bus ********************************/

#define METH_BUS_ATTR_DEF(name, op2)                            \
    static int bus_set_ ## name(lua_State *L)                   \
    {                                                           \
        sd_bus *bus = tobus(L, 1);                              \
        int b = lua_toboolean(L, 2);                            \
        int err = sd_bus_set_ ## name(bus, b);                  \
        if (err < 0) {                                          \
            lua_pushnil(L);                                     \
            lua_pushinteger(L, -err);                           \
            return 2;                                           \
        }                                                       \
        return 1;                                               \
    }                                                           \
    static int bus_ ## op2 ## _ ## name(lua_State *L)           \
    {                                                           \
        sd_bus *bus = tobus(L, 1);                              \
        lua_pushboolean(L, sd_bus_ ## op2 ## _ ## name(bus));   \
        return 1;                                               \
    }

/*
METH_BUS_ATTR_DEF(bus_client, is)
METH_BUS_ATTR_DEF(anonymous, is)
METH_BUS_ATTR_DEF(trusted, is)
METH_BUS_ATTR_DEF(monitor, is)
*/
METH_BUS_ATTR_DEF(allow_interactive_authorization, get)
/*
METH_BUS_ATTR_DEF(exit_on_disconnect, get)
METH_BUS_ATTR_DEF(close_on_exit, get)
METH_BUS_ATTR_DEF(watch_bind, get)
METH_BUS_ATTR_DEF(connected_signal, get)
*/

static int bus_set_address(lua_State *L)
{
    sd_bus *bus = tobus(L, 1);
    const char *address = luaL_checkstring(L, 2);
    int err = sd_bus_set_address(bus, address);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    lua_settop(L, 1);
    return 1;
}

static int getpeercred(int fd, struct ucred *ucred)
{
    socklen_t n = sizeof(struct ucred);
    struct ucred u;
    int err;

    err = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &u, &n);
    if (err < 0)
        return -errno;

    if (n != sizeof(struct ucred))
        return -EIO;

    if (u.pid <= 0)
        return -ENODATA;

    *ucred = u;
    return 0;
}

static int do_bus_check_peercred(sd_bus *bus)
{
    struct ucred ucred;
    int fd;
    int err;

    fd = sd_bus_get_fd(bus);
    if (fd < 0)
        return fd;

    err = getpeercred(fd, &ucred);
    if (err < 0)
        return err;

    if (ucred.uid != 0 && ucred.uid != geteuid())
        return -EPERM;

    return 0;
}

static int bus_check_peercred(lua_State *L)
{
    sd_bus *bus = tobus(L, 1);
    int err = do_bus_check_peercred(bus);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    lua_settop(L, 1);
    return 1;
}

static int bus_start(lua_State *L)
{
    sd_bus *bus = tobus(L, 1);
    int err = sd_bus_start(bus);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    lua_settop(L, 1);
    return 1;
}

static int bus_message_new(lua_State *L)
{
    sd_bus *bus = tobus(L, 1);
    int type = luaL_checkinteger(L, 2);
    sd_bus_message **mp = newmessage(L);
    int err = sd_bus_message_new(bus, mp, (uint8_t)type);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    return 1;
}

static int bus_message_new_signal(lua_State *L)
{
    sd_bus *bus = tobus(L, 1);
    const char *path = luaL_checkstring(L, 2);
    const char *interface = luaL_checkstring(L, 3);
    const char *member = luaL_checkstring(L, 4);
    sd_bus_message **mp = newmessage(L);
    int err = sd_bus_message_new_signal(bus, mp, path, interface, member);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    return 1;
}

/*
static int bus_message_new_signal_to(lua_State *L)
{
    sd_bus *bus = tobus(L, 1);
    const char *destination = luaL_checkstring(L, 2);
    const char *path = luaL_checkstring(L, 3);
    const char *interface = luaL_checkstring(L, 4);
    const char *member = luaL_checkstring(L, 5);
    sd_bus_message **mp = newmessage(L);
    int err = sd_bus_message_new_signal_to(bus, mp, destination,
                                           path, interface, member);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    return 1;
}
*/

static int bus_message_new_method_call(lua_State *L)
{
    sd_bus *bus = tobus(L, 1);
    const char *destination = luaL_checkstring(L, 2);
    const char *path = luaL_checkstring(L, 3);
    const char *interface = luaL_checkstring(L, 4);
    const char *member = luaL_checkstring(L, 5);
    sd_bus_message **mp = newmessage(L);
    int err = sd_bus_message_new_method_call(bus, mp, destination,
                                             path, interface, member);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    return 1;
}

static int bus_call(lua_State *L)
{
    sd_bus *bus = tobus(L, 1);
    sd_bus_message *m = tomessage(L, 2);
    uint64_t usec = (uint64_t)luaL_optlong(L, 3, 0);
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message **replyp = newmessage(L);
    int err = sd_bus_call(bus, m, usec, &error, replyp);
    sd_bus_error_free(&error);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    return 1;
}

static int bus_call_async(lua_State *L)
{
    /* TODO */
    return 0;
}

static int bus_unit_filestate(lua_State *L)
{
    sd_bus *bus = tobus(L, 1);
    const char *name = luaL_checkstring(L, 2);
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message **replyp = newmessage(L);
    int err = sd_bus_call_method(bus, "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
            "GetUnitFileState", &error, replyp, "s", name);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }
    return 1;
}

/* FIXME TODO: close_unref ? */
static int bus_close(lua_State *L)
{
    sd_bus *bus = tobus(L, 1);
    sd_bus_close(bus);
    return 0;
}

static const luaL_Reg bus_meth[] = {
    { "set_allow_interactive_authorization",
                        bus_set_allow_interactive_authorization },
    { "get_allow_interactive_authorization",
                        bus_get_allow_interactive_authorization },
    { "set_address",                bus_set_address             },
    { "check_peercred",             bus_check_peercred          },
    { "start",                      bus_start                   },
    { "message_new",                bus_message_new             },
    { "message_new_signal",         bus_message_new_signal      },
    /*{ "message_new_signal_to",      bus_message_new_signal_to   },*/
    { "message_new_method_call",    bus_message_new_method_call },
    { "call",                       bus_call                    },
    { "call_async",                 bus_call_async              },
    { "unit_filestate",             bus_unit_filestate          },
    { "__gc",                       bus_close                   },
    { NULL, NULL }
};

/******************************** systemd ********************************/

static int daemon_sd_booted(lua_State *L)
{
    int err = sd_booted();
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    } else {
        lua_pushboolean(L, err);
        return 1;
    }
}

#define BUS_FUNCTION_DEF(name)                                  \
    static int bus_ ## name(lua_State *L)                       \
    {                                                           \
        sd_bus **bus = newbus(L);                               \
        int err = sd_bus_ ## name(bus);                         \
        if (err < 0) {                                          \
            lua_pushnil(L);                                     \
            lua_pushinteger(L, -err);                           \
            return 2;                                           \
        }                                                       \
        return 1;                                               \
    }

#define BUS_FUNCTION_WITH_ARGS_DEF(name)                        \
    static int bus_ ## name(lua_State *L)                       \
    {                                                           \
        const char *s = luaL_checkstring(L, 1);                 \
        sd_bus **bus = newbus(L);                               \
        int err = sd_bus_ ## name(bus, s);                      \
        if (err < 0) {                                          \
            lua_pushnil(L);                                     \
            lua_pushinteger(L, -err);                           \
            return 2;                                           \
        }                                                       \
        return 1;                                               \
    }

BUS_FUNCTION_DEF(default)
BUS_FUNCTION_DEF(default_user)
BUS_FUNCTION_DEF(default_system)
BUS_FUNCTION_DEF(open)
BUS_FUNCTION_DEF(open_user)
BUS_FUNCTION_DEF(open_system)
BUS_FUNCTION_DEF(new)
BUS_FUNCTION_WITH_ARGS_DEF(open_with_description)
BUS_FUNCTION_WITH_ARGS_DEF(open_user_with_description)
/*BUS_FUNCTION_WITH_ARGS_DEF(open_user_machine)*/
BUS_FUNCTION_WITH_ARGS_DEF(open_system_with_description)
BUS_FUNCTION_WITH_ARGS_DEF(open_system_remote)
BUS_FUNCTION_WITH_ARGS_DEF(open_system_machine)

static const luaL_Reg systemdlib[] = {
    { "sd_booted",                        daemon_sd_booted                 },
    { "bus_default",                      bus_default                      },
    { "bus_default_user",                 bus_default_user                 },
    { "bus_default_system",               bus_default_system               },
    { "bus_open",                         bus_open                         },
    { "bus_open_with_description",        bus_open_with_description        },
    { "bus_open_user",                    bus_open_user                    },
    { "bus_open_user_with_description",   bus_open_user_with_description   },
    /*{ "bus_open_user_machine",            bus_open_user_machine            },*/
    { "bus_open_system",                  bus_open_system                  },
    { "bus_open_system_with_description", bus_open_system_with_description },
    { "bus_open_system_remote",           bus_open_system_remote           },
    { "bus_open_system_machine",          bus_open_system_machine          },
    { "bus_new",                          bus_new                          },
    { NULL, NULL }
};

LUALIB_API int luaopen_systemd(lua_State *L)
{
    luaL_newlib(L, systemdlib);

    createmeta(L, METH_SYSTEMD_BUS, bus_meth);
    createmeta(L, METH_SYSTEMD_MESSAGE, message_meth);

    return 1;
}
