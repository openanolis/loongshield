#include <stdbool.h>
#include <dbus/dbus.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <compat-5.3.h>
#include "luauxlib.h"

#define METH_DBUS_CONNECTION    "meth_dbus_connection"
#define METH_DBUS_MESSAGE       "meth_dbus_message"
#define METH_DBUS_PENDING       "meth_dbus_pending"

#define newconnection(L)  (DBusConnection **)newcptr((L), METH_DBUS_CONNECTION)
#define newmessage(L)     (DBusMessage **)newcptr((L), METH_DBUS_MESSAGE)
#define newpending(L)     (DBusPendingCall **)newcptr((L), METH_DBUS_PENDING)

#define toconnectionp(L, idx)   \
    (DBusConnection **)luaL_checkudata((L), (idx), METH_DBUS_CONNECTION)
#define tomessagep(L, idx)      \
    (DBusMessage **)luaL_checkudata((L), (idx), METH_DBUS_MESSAGE)
#define topendingp(L, idx)      \
    (DBusPendingCall **)luaL_checkudata((L), (idx), METH_DBUS_PENDING)

#define toconnection(L, idx)    (*toconnectionp(L, idx))
#define tomessage(L, idx)       (*tomessagep(L, idx))
#define topending(L, idx)       (*topendingp(L, idx))

static int dbus_result(lua_State *L, DBusError *error, int nres)
{
    if (dbus_error_is_set(error)) {
        lua_pushnil(L);
        lua_pushfstring(L, "%s: %s", error->name, error->message);
        nres = 2;
    }
    dbus_error_free(error);
    return nres;
}

/********************************* message *********************************/

static int message_free(lua_State *L)
{
    DBusMessage **mp = tomessagep(L, 1);
    if (*mp) {
        dbus_message_unref(*mp);
        *mp = NULL;
    }
    return 0;
}

static int message_type(lua_State *L)
{
    DBusMessage *m = tomessage(L, 1);
    int type = dbus_message_get_type(m);
    lua_pushstring(L, dbus_message_type_to_string(type));
    return 1;
}

static int message_new_method_return(lua_State *L)
{
    DBusMessage *m = tomessage(L, 1);
    DBusMessage **mp = newmessage(L);
    *mp = dbus_message_new_method_return(m);
    if (*mp == NULL)
        return 0;
    return 1;
}

static int message_new_error(lua_State *L)
{
    DBusMessage *m = tomessage(L, 1);
    const char *name = luaL_checkstring(L, 2);
    const char *message = luaL_checkstring(L, 3);
    DBusMessage **mp = newmessage(L);
    *mp = dbus_message_new_error(m, name, message);
    if (*mp == NULL)
        return 0;
    return 1;
}

static int message_append(lua_State *L)
{
    DBusMessage *m = tomessage(L, 1);
    DBusMessageIter args;
    int top = lua_gettop(L);
    int idx;
    dbus_message_iter_init_append(m, &args);
    for (idx = 2; idx <= top; idx++) {
        const char *s;
        dbus_int32_t num;
        dbus_bool_t b;
        dbus_bool_t r;
        switch (lua_type(L, idx)) {
        case LUA_TBOOLEAN:
            b = lua_toboolean(L, idx);
            r = dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &b);
            break;
        case LUA_TNUMBER:
            num = (dbus_int32_t)lua_tointeger(L, idx);
            r = dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, &num);
            break;
        case LUA_TSTRING:
            s = lua_tostring(L, idx);
            r = dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &s);
            break;
        default:
            r = false;
            break;
        }
        if (!r)
            return 0;
    }
    lua_settop(L, 1);
    return 1;
}

static int message_decode(lua_State *L)
{
    DBusMessage *m = tomessage(L, 1);
    DBusMessageIter args;
    if (!dbus_message_iter_init(m, &args))
        return 0;           /* No arguments */
    lua_newtable(L);
    do {
        const char *s;
        dbus_uint32_t num;
        dbus_bool_t b;
        int type = dbus_message_iter_get_arg_type(&args);
        switch (type) {
        case DBUS_TYPE_BOOLEAN:
            dbus_message_iter_get_basic(&args, &b);
            lua_pushboolean(L, b);
            lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
            break;
        case DBUS_TYPE_INT32:
        case DBUS_TYPE_UINT32:
            dbus_message_iter_get_basic(&args, &num);
            lua_pushinteger(L, num);
            lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
            break;
        case DBUS_TYPE_STRING:
        case DBUS_TYPE_OBJECT_PATH:
            dbus_message_iter_get_basic(&args, &s);
            lua_pushstring(L, s);
            lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
            break;
        default:
            /* TODO: return unknown type */
            lua_pushnil(L);
            lua_pushinteger(L, type);
            return 2;
        }
    } while (dbus_message_iter_next(&args));
    return 1;
}

static int message_is_method_call_or_signal(lua_State *L, int method_call)
{
    DBusMessage *m = tomessage(L, 1);
    const char *iface = luaL_checkstring(L, 2);
    const char *name = luaL_checkstring(L, 3);
    dbus_bool_t r;
    if (method_call)
        r = dbus_message_is_method_call(m, iface, name);
    else
        r = dbus_message_is_signal(m, iface, name);
    lua_pushboolean(L, r);
    return 1;
}

static int message_is_method_call(lua_State *L)
{
    return message_is_method_call_or_signal(L, 1);
}

static int message_is_signal(lua_State *L)
{
    return message_is_method_call_or_signal(L, 0);
}

static int message_marshal(lua_State *L)
{
    DBusMessage *m = tomessage(L, 1);
    char *p = NULL;
    int len = 0;
    if (!dbus_message_marshal(m, &p, &len))
        return 0;
    lua_pushlstring(L, p, len);
    dbus_free(p);
    return 1;
}


#define DEF_MESSAGE_METH(name, type)                                        \
    static int message_ ## name(lua_State *L)                               \
    {                                                                       \
        DBusMessage *m = tomessage(L, 1);                                   \
        if (lua_gettop(L) >= 2)                                             \
            lua_pushboolean(L,                                              \
                dbus_message_set_ ## name(m, luaL_check ## type(L, 2)));    \
        else                                                                \
            lua_push ## type(L, dbus_message_get_ ## name(m));              \
        return 1;                                                           \
    }

#define DEF_MESSAGE_METH_VOID(name, type)                                   \
    static int message_ ## name(lua_State *L)                               \
    {                                                                       \
        DBusMessage *m = tomessage(L, 1);                                   \
        if (lua_gettop(L) >= 2) {                                           \
            dbus_message_set_ ## name(m, lua_to ## type(L, 2));             \
            return 0;                                                       \
        } else {                                                            \
            lua_push ## type(L, dbus_message_get_ ## name(m));              \
            return 1;                                                       \
        }                                                                   \
    }

#define DEF_MESSAGE_METH_IS(name, type)                                     \
    static int message_ ## name(lua_State *L)                               \
    {                                                                       \
        DBusMessage *m = tomessage(L, 1);                                   \
        lua_pushboolean(L,                                                  \
            dbus_message_ ## name(m, luaL_check ## type(L, 2)));            \
        return 1;                                                           \
    }

#define MESSAGE_METH_LISTS                                                  \
    XX(DEF_MESSAGE_METH_IS,     has_path,           string)                 \
    XX(DEF_MESSAGE_METH_IS,     has_interface,      string)                 \
    XX(DEF_MESSAGE_METH_IS,     has_member,         string)                 \
    XX(DEF_MESSAGE_METH_IS,     has_destination,    string)                 \
    XX(DEF_MESSAGE_METH_IS,     has_sender,         string)                 \
    XX(DEF_MESSAGE_METH_IS,     has_signature,      string)                 \
    XX(DEF_MESSAGE_METH_IS,     is_error,           string)                 \
    XX(DEF_MESSAGE_METH,        path,               string)                 \
    XX(DEF_MESSAGE_METH,        interface,          string)                 \
    XX(DEF_MESSAGE_METH,        member,             string)                 \
    XX(DEF_MESSAGE_METH,        error_name,         string)                 \
    XX(DEF_MESSAGE_METH,        destination,        string)                 \
    XX(DEF_MESSAGE_METH,        sender,             string)                 \
    /* XX(DEF_MESSAGE_METH,        container_instance, string) */           \
    XX(DEF_MESSAGE_METH_VOID,   serial,             integer) /* uint32_t */ \
    XX(DEF_MESSAGE_METH_VOID,   reply_serial,       integer) /* uint32_t */ \
    XX(DEF_MESSAGE_METH_VOID,   no_reply,           boolean)                \
    XX(DEF_MESSAGE_METH_VOID,   auto_start,         boolean)                \
    XX(DEF_MESSAGE_METH_VOID,   allow_interactive_authorization, boolean)

#define XX(macro, name, ...)        macro(name, ##__VA_ARGS__)
MESSAGE_METH_LISTS
#undef XX

static const luaL_Reg message_meth[] = {
    { "__gc",              message_free              },
    { "type",              message_type              },
    { "new_method_return", message_new_method_return },
    { "new_error",         message_new_error         },
    { "append",            message_append            },
    { "decode",            message_decode            },
    { "is_method_call",    message_is_method_call    },
    { "is_signal",         message_is_signal         },
    { "marshal",           message_marshal           },

#define XX(macro, name, ...)        { #name, message_ ## name },
MESSAGE_METH_LISTS
#undef XX
    { NULL, NULL }
};

static int luadbus_message_new(lua_State *L)
{
    const char *type = luaL_checkstring(L, 1);
    DBusMessage **mp = newmessage(L);
    *mp = dbus_message_new(dbus_message_type_from_string(type));
    if (*mp == NULL)
        return 0;
    return 1;
}

static int luadbus_message_new_method_call(lua_State *L)
{
    const char *bus_name = luaL_checkstring(L, 1);
    const char *path     = luaL_checkstring(L, 2);
    const char *iface    = luaL_checkstring(L, 3);
    const char *method   = luaL_checkstring(L, 4);
    DBusMessage **mp = newmessage(L);
    *mp = dbus_message_new_method_call(bus_name, path, iface, method);
    if (*mp == NULL)
        return 0;
    return 1;
}

static int luadbus_message_new_signal(lua_State *L)
{
    const char *path  = luaL_checkstring(L, 1);
    const char *iface = luaL_checkstring(L, 2);
    const char *name  = luaL_checkstring(L, 3);
    DBusMessage **mp = newmessage(L);
    *mp = dbus_message_new_signal(path, iface, name);
    if (*mp == NULL)
        return 0;
    return 1;
}

static int luadbus_message_demarshal(lua_State *L)
{
    size_t len;
    const char *s = luaL_checklstring(L, 1, &len);
    DBusMessage **mp = newmessage(L);
    DBusError error;
    dbus_error_init(&error);
    *mp = dbus_message_demarshal(s, len, &error);
    return dbus_result(L, &error, 1);
}

/******************************* pending call ******************************/

static int pending_free(lua_State *L)
{
    DBusPendingCall **pendingp = topendingp(L, 1);
    if (*pendingp) {
        dbus_pending_call_unref(*pendingp);
        *pendingp = NULL;
    }
    return 0;
}

struct notify_userdata {
    lua_State *L;
    int ref;
};

static void pending_call_notify(DBusPendingCall *pending, void *userdata)
{
    struct notify_userdata *ud = userdata;
    lua_State *L = ud->L;
    lua_rawgeti(L, LUA_REGISTRYINDEX, ud->ref);
    lua_call(L, 0, 0);
    luaL_unref(L, LUA_REGISTRYINDEX, ud->ref);
    return;
}

static int pending_set_notify(lua_State *L)
{
    DBusPendingCall *pending = topending(L, 1);
    dbus_bool_t r;
    struct notify_userdata *ud;
    if ((ud = dbus_malloc(sizeof(*ud))) == NULL)
        return 0;
    lua_pushvalue(L, 2);
    ud->ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ud->L = L;
    r = dbus_pending_call_set_notify(pending,
                                     pending_call_notify, ud, dbus_free);
    lua_pushboolean(L, r);
    return 1;
}

static int pending_cancel(lua_State *L)
{
    DBusPendingCall *pending = topending(L, 1);
    dbus_pending_call_cancel(pending);
    return 0;
}

static int pending_completed(lua_State *L)
{
    DBusPendingCall *pending = topending(L, 1);
    lua_pushboolean(L, dbus_pending_call_get_completed(pending));
    return 1;
}

static int pending_steal_reply(lua_State *L)
{
    DBusPendingCall *pending = topending(L, 1);
    DBusMessage **mp = newmessage(L);
    *mp = dbus_pending_call_steal_reply(pending);
    if (*mp == NULL)
        return 0;
    return 1;
}

static int pending_block(lua_State *L)
{
    DBusPendingCall *pending = topending(L, 1);
    dbus_pending_call_block(pending);
    return 0;
}

static const luaL_Reg pending_meth[] = {
    { "__gc",        pending_free        },
    { "set_notify",  pending_set_notify  },
    { "cancel",      pending_cancel      },
    { "completed",   pending_completed   },
    { "steal_reply", pending_steal_reply },
    { "block",       pending_block       },
    { NULL, NULL }
};

/******************************** connection *******************************/

static int connection_free(lua_State *L)
{
    DBusConnection **conp = toconnectionp(L, 1);
    if (*conp) {
        dbus_connection_unref(*conp);
        *conp = NULL;
    }
    return 0;
}

static int connection_flush(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    dbus_connection_flush(con);
    return 0;
}

static int connection_read_write_dispatch(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    int timeout = luaL_optinteger(L, 2, 0);     /* milliseconds */
    lua_pushboolean(L, dbus_connection_read_write_dispatch(con, timeout));
    return 1;
}

static int connection_read_write(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    int timeout = luaL_optinteger(L, 2, 0);     /* milliseconds */
    lua_pushboolean(L, dbus_connection_read_write(con, timeout));
    return 1;
}

static int connection_borrow_message(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    DBusMessage **mp = newmessage(L);
    *mp = dbus_connection_borrow_message(con);
    if (*mp == NULL)
        return 0;
    return 1;
}

static int connection_pop_message(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    DBusMessage **mp = newmessage(L);
    *mp = dbus_connection_pop_message(con);
    if (*mp == NULL)
        return 0;
    return 1;
}

static int connection_dispatch_common(lua_State *L, int dispatch)
{
    DBusConnection *con = toconnection(L, 1);
    DBusDispatchStatus status;
    const char *s;
    if (dispatch)
        status = dbus_connection_dispatch(con);
    else
        status = dbus_connection_get_dispatch_status(con);
    switch (status) {
    case DBUS_DISPATCH_DATA_REMAINS: s = "data_remains"; break;
    case DBUS_DISPATCH_COMPLETE:     s = "complete";     break;
    case DBUS_DISPATCH_NEED_MEMORY:  s = "need_memory";  break;
    }
    lua_pushstring(L, s);
    return 1;
}

static int connection_dispatch_status(lua_State *L)
{
    return connection_dispatch_common(L, 0);
}

static int connection_dispatch(lua_State *L)
{
    return connection_dispatch_common(L, 1);
}

/*
 * usage:
 *   con:send(message, serial, true)
 *   con:send(message, true)
 *   con:send(message)
 */
static int connection_send(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    DBusMessage *m = tomessage(L, 2);
    dbus_uint32_t serial;
    int flush;
    dbus_bool_t r;
    if (lua_gettop(L) >= 4) {
        serial = luaL_checkinteger(L, 3);
        flush = lua_toboolean(L, 4);
    } else {
        serial = 0;
        flush = lua_toboolean(L, 3);
    }
    r = dbus_connection_send(con, m, &serial);
    if (flush && r)
        dbus_connection_flush(con);
    lua_pushboolean(L, r);
    return 1;
}

/*
 * usage:
 *   pending = con:send_with_reply(message, 100, true)
 *   pending = con:send_with_reply(message, true)   -- -1 is default timeout
 *   pending = con:send_with_reply(message)
 */
static int connection_send_with_reply(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    DBusMessage *m = tomessage(L, 2);
    DBusPendingCall **pendingp;
    int timeout;
    int flush;
    dbus_bool_t r;
    if (lua_gettop(L) >= 4) {
        timeout = luaL_checkinteger(L, 3);      /* milliseconds */
        flush = lua_toboolean(L, 4);
    } else {
        timeout = -1;
        flush = lua_toboolean(L, 3);
    }
    pendingp = newpending(L);
    r = dbus_connection_send_with_reply(con, m, pendingp, timeout);
    if (!r || *pendingp == NULL)
        return 0;
    if (flush)
        dbus_connection_flush(con);
    return 1;
}

static int connection_send_with_reply_and_block(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    DBusMessage *m = tomessage(L, 2);
    int timeout = luaL_optinteger(L, 3, 0);     /* milliseconds */
    DBusMessage **mp = newmessage(L);
    DBusError error;
    dbus_error_init(&error);
    *mp = dbus_connection_send_with_reply_and_block(con, m, timeout, &error);
    return dbus_result(L, &error, 1);
}

static int connection_unix_user(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    unsigned long uid;
    if (dbus_connection_get_unix_user(con, &uid)) {
        lua_pushinteger(L, uid);
        return 1;
    }
    return 0;
}

static int connection_unix_process_id(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    unsigned long pid;
    if (dbus_connection_get_unix_process_id(con, &pid)) {
        lua_pushinteger(L, pid);
        return 1;
    }
    return 0;
}

static int connection_allow_anonymous(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    int v = lua_toboolean(L, 2);
    dbus_connection_set_allow_anonymous(con, v);
    return 0;
}

static int connection_unix_fd(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    int fd;
    if (dbus_connection_get_unix_fd(con, &fd)) {
        lua_pushinteger(L, fd);
        return 1;
    }
    return 0;
}

static int connection_socket(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    int fd;
    if (dbus_connection_get_socket(con, &fd)) {
        lua_pushinteger(L, fd);
        return 1;
    }
    return 0;
}

/*
static int connection_(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
}
*/

/*********************************** bus ***********************************/

static int bus_register(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    DBusError error;
    dbus_error_init(&error);
    dbus_bus_register(con, &error);
    lua_settop(L, 1);       /* return the connection */
    return dbus_result(L, &error, 1);
}

static int bus_unique_name(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    const char *name;
    if (lua_gettop(L) == 1) {
        if (name = dbus_bus_get_unique_name(con))
            lua_pushstring(L, name);
        else
            lua_pushnil(L);
    } else {
        name = luaL_checkstring(L, 2);
        lua_pushboolean(L, dbus_bus_set_unique_name(con, name));
    }
    return 1;
}

static int bus_unix_user(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    const char *name = luaL_checkstring(L, 2);
    unsigned long uid;
    DBusError error;
    dbus_error_init(&error);
    uid = dbus_bus_get_unix_user(con, name, &error);
    if (uid != -1)
        lua_pushinteger(L, uid);
    return dbus_result(L, &error, 1);
}

static int bus_id(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    char *id;
    DBusError error;
    dbus_error_init(&error);
    id = dbus_bus_get_id(con, &error);
    if (id)
        lua_pushstring(L, id);
    return dbus_result(L, &error, 1);
}

static int bus_request_name(lua_State *L)
{
    static const struct cflag_opt opts[] = {
        { "allow",   DBUS_NAME_FLAG_ALLOW_REPLACEMENT },
        { "replace", DBUS_NAME_FLAG_REPLACE_EXISTING  },
        { "noqueue", DBUS_NAME_FLAG_DO_NOT_QUEUE      },
        { NULL, 0 }
    };
    DBusConnection *con = toconnection(L, 1);
    const char *name = luaL_checkstring(L, 2);
    unsigned int flags = tocflags(L, 3, opts, DBUS_NAME_FLAG_REPLACE_EXISTING);
    int ret;
    const char *s = NULL;
    DBusError error;
    dbus_error_init(&error);
    ret = dbus_bus_request_name(con, name, flags, &error);
    switch (ret) {
    case DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER: s = "primary"; break;
    case DBUS_REQUEST_NAME_REPLY_IN_QUEUE:      s = "inqueue"; break;
    case DBUS_REQUEST_NAME_REPLY_EXISTS:        s = "exists";  break;
    case DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER: s = "already"; break;
    }
    lua_pushstring(L, s);
    return dbus_result(L, &error, 1);
}

static int bus_release_name(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    const char *name = luaL_checkstring(L, 2);
    int ret;
    const char *s = NULL;
    DBusError error;
    dbus_error_init(&error);
    ret = dbus_bus_release_name(con, name, &error);
    switch (ret) {
    case DBUS_RELEASE_NAME_REPLY_RELEASED:     s = "released"; break;
    case DBUS_RELEASE_NAME_REPLY_NON_EXISTENT: s = "noexist";  break;
    case DBUS_RELEASE_NAME_REPLY_NOT_OWNER:    s = "notowner"; break;
    }
    lua_pushstring(L, s);
    return dbus_result(L, &error, 1);
}

static int bus_name_has_owner(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    const char *name = luaL_checkstring(L, 2);
    DBusError error;
    dbus_error_init(&error);
    lua_pushboolean(L, dbus_bus_name_has_owner(con, name, &error));
    return dbus_result(L, &error, 1);
}

static int bus_start_service_by_name(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    const char *name = luaL_checkstring(L, 2);
    dbus_uint32_t flags = luaL_optinteger(L, 3, 0);
    dbus_uint32_t reply = 0;
    const char *s = NULL;
    dbus_bool_t r;
    DBusError error;
    dbus_error_init(&error);
    r = dbus_bus_start_service_by_name(con, name, flags, &reply, &error);
    switch (reply) {
    case DBUS_START_REPLY_SUCCESS:         s = "success"; break;
    case DBUS_START_REPLY_ALREADY_RUNNING: s = "already"; break;
    }
    lua_pushboolean(L, r);
    lua_pushstring(L, s);
    return dbus_result(L, &error, 2);
}

static int bus_add_match(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    const char *rule = luaL_checkstring(L, 2);
    DBusError error;
    dbus_error_init(&error);
    dbus_bus_add_match(con, rule, &error);
    lua_pushboolean(L, 1);
    return dbus_result(L, &error, 1);
}

static int bus_remove_match(lua_State *L)
{
    DBusConnection *con = toconnection(L, 1);
    const char *rule = luaL_checkstring(L, 2);
    DBusError error;
    dbus_error_init(&error);
    dbus_bus_remove_match(con, rule, &error);
    lua_pushboolean(L, 1);
    return dbus_result(L, &error, 1);
}


static const luaL_Reg connection_meth[] = {
    { "__gc",                      connection_free                      },
    { "flush",                     connection_flush                     },
    { "read_write_dispatch",       connection_read_write_dispatch       },
    { "read_write",                connection_read_write                },
    { "borrow_message",            connection_borrow_message            },
    { "pop_message",               connection_pop_message               },
    { "dispatch_status",           connection_dispatch_status           },
    { "dispatch",                  connection_dispatch                  },
    { "send",                      connection_send                      },
    { "send_with_reply",           connection_send_with_reply           },
    { "send_with_reply_and_block", connection_send_with_reply_and_block },
    { "unix_user",                 connection_unix_user                 },
    { "unix_process_id",           connection_unix_process_id           },
    { "allow_anonymous",           connection_allow_anonymous           },
    { "unix_fd",                   connection_unix_fd                   },
    { "socket",                    connection_socket                    },

    { "register",                  bus_register                         },
    { "unique_name",               bus_unique_name                      },
    { "unix_user",                 bus_unix_user                        },
    { "id",                        bus_id                               },
    { "request_name",              bus_request_name                     },
    { "release_name",              bus_release_name                     },
    { "name_has_owner",            bus_name_has_owner                   },
    { "start_service_by_name",     bus_start_service_by_name            },
    { "add_match",                 bus_add_match                        },
    { "remove_match",              bus_remove_match                     },
    { NULL, NULL }
};

static int luadbus_connection_open_common(lua_State *L, int private)
{
    const char *address = luaL_checkstring(L, 1);
    DBusConnection **conp = newconnection(L);
    DBusError error;
    dbus_error_init(&error);
    if (private)
        *conp = dbus_connection_open_private(address, &error);
    else
        *conp = dbus_connection_open(address, &error);
    return dbus_result(L, &error, 1);
}

static int luadbus_connection_open(lua_State *L)
{
    return luadbus_connection_open_common(L, 0);
}

static int luadbus_connection_open_private(lua_State *L)
{
    return luadbus_connection_open_common(L, 1);
}

static int luadbus_bus_get_common(lua_State *L, int private)
{
    static const struct cflag_opt opts[] = {
        { "session", DBUS_BUS_SESSION },
        { "system",  DBUS_BUS_SYSTEM  },
        { "starter", DBUS_BUS_STARTER },
        { NULL, 0 }
    };
    DBusBusType type = (DBusBusType)tocflags(L, 1, opts, DBUS_BUS_SESSION);
    DBusConnection **conp = newconnection(L);
    DBusError error;
    dbus_error_init(&error);
    if (private)
        *conp = dbus_bus_get_private(type, &error);
    else
        *conp = dbus_bus_get(type, &error);
    return dbus_result(L, &error, 1);
}

static int luadbus_bus_get(lua_State *L)
{
    return luadbus_bus_get_common(L, 0);
}

static int luadbus_bus_get_private(lua_State *L)
{
    return luadbus_bus_get_common(L, 1);
}

/*********************************** main **********************************/

static int luadbus_version(lua_State *L)
{
    int major, minor, micro;
    dbus_get_version(&major, &minor, &micro);
    lua_pushinteger(L, major);
    lua_pushinteger(L, minor);
    lua_pushinteger(L, micro);
    return 3;
}

static int luadbus_local_machine_id(lua_State *L)
{
    char *lmid;
    DBusError error;
    dbus_error_init(&error);
    lmid = dbus_try_get_local_machine_id(&error);
    lua_pushstring(L, lmid);
    return dbus_result(L, &error, 1);
}

static int luadbus_setenv(lua_State *L)
{
    const char *var = luaL_checkstring(L, 1);
    const char *val = luaL_checkstring(L, 2);
    lua_pushboolean(L, dbus_setenv(var, val));
    return 1;
}


static const luaL_Reg dbuslib[] = {
    { "version",                    luadbus_version                 },
    { "local_machine_id",           luadbus_local_machine_id        },
    { "setenv",                     luadbus_setenv                  },
    { "bus_get",                    luadbus_bus_get                 },
    { "bus_get_private",            luadbus_bus_get_private         },
    { "connection_open",            luadbus_connection_open         },
    { "connection_open_private",    luadbus_connection_open_private },
    { "message_new",                luadbus_message_new             },
    { "message_new_method_call",    luadbus_message_new_method_call },
    { "message_new_signal",         luadbus_message_new_signal      },
    { "message_demarshal",          luadbus_message_demarshal       },
    { NULL, NULL }
};

LUALIB_API int luaopen_dbus(lua_State *L)
{
    luaL_newlib(L, dbuslib);

    createmeta(L, METH_DBUS_CONNECTION, connection_meth);
    createmeta(L, METH_DBUS_MESSAGE, message_meth);
    createmeta(L, METH_DBUS_PENDING, pending_meth);

    return 1;
}
