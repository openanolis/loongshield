#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/cms.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <compat-5.3.h>

#include "luauxlib.h"

#include <libkmod/libkmod.h>


#define METH_KMOD_CTX                   "meth_kmod_ctx"
#define METH_KMOD_CONFIG                "meth_kmod_config"
#define METH_KMOD_MODULE                "meth_kmod_module"
#define METH_KMOD_LIST_MODULE           "meth_kmod_list_module"
#define METH_KMOD_LIST_MOD_SECTION      "meth_kmod_list_mod_section"
#define METH_KMOD_LIST_MOD_INFO         "meth_kmod_list_mod_info"
#define METH_KMOD_LIST_MOD_VERSION      "meth_kmod_list_mod_version"
#define METH_KMOD_LIST_MOD_SYMBOL       "meth_kmod_list_mod_symbol"
#define METH_KMOD_LIST_MOD_DEP_SYMBOL   "meth_kmod_list_mod_dep_symbol"


struct list {
    struct kmod_list *head;
    struct kmod_list *list;
};

static struct list *newlist(lua_State *L, const char *metatable)
{
    struct list *l = (struct list *)lua_newuserdata(L, sizeof(*l));
    l->head = NULL;
    l->list = NULL;
    luaL_getmetatable(L, metatable);
    lua_setmetatable(L, -2);
    return l;
}

#define tolist(L, idx, t)   ((struct list *)luaL_checkudata((L), (idx), (t)))


#define newctx(L)    (struct kmod_ctx **)newcptr((L), METH_KMOD_CTX)
#define newconfig(L) (struct kmod_config_iter **)newcptr((L), METH_KMOD_CONFIG)
#define newmodule(L) (struct kmod_module **)newcptr((L), METH_KMOD_MODULE)

#define toctx(L, idx)       \
    (*(struct kmod_ctx **)luaL_checkudata((L), (idx), METH_KMOD_CTX))
#define toconfig(L, idx)    \
    (*(struct kmod_config_iter **)luaL_checkudata((L), (idx), METH_KMOD_CONFIG))
#define tomodule(L, idx)    \
    (*(struct kmod_module **)luaL_checkudata((L), (idx), METH_KMOD_MODULE))


/*
static int list_new(lua_State *L, struct kmod_list *list)
{
    if (list == NULL) {
        lua_pushnil(L);
    } else {
        struct kmodlist *l;
        l = (struct kmodlist *)lua_newuserdata(L, sizeof(*l));
        l->list = list;
        luaL_getmetatable(L, METH_LIBKMOD_LIST);
        lua_setmetatable(L, -2);
    }
    return 1;
}
*/

static int kmod_error(lua_State *L, int err)
{
    lua_pushnil(L);
    lua_pushinteger(L, err);
    lua_pushstring(L, strerror(err));
    return 3;
}

/******************************** ctx ********************************/

static int ctx_unref(lua_State *L)
{
    struct kmod_ctx *ctx = toctx(L, 1);
    kmod_unref(ctx);
    return 0;
}

static int ctx_dirname(lua_State *L)
{
    const struct kmod_ctx *ctx = toctx(L, 1);
    lua_pushstring(L, kmod_get_dirname(ctx));
    return 1;
}

static int ctx_load_resources(lua_State *L)
{
    struct kmod_ctx *ctx = toctx(L, 1);
    int err = kmod_load_resources(ctx);
    if (err < 0)
        return kmod_error(L, -err);
    lua_pushboolean(L, 1);
    return 1;
}

static int ctx_unload_resources(lua_State *L)
{
    struct kmod_ctx *ctx = toctx(L, 1);
    kmod_unload_resources(ctx);
    return 0;
}

static int ctx_validate_resources(lua_State *L)
{
    struct kmod_ctx *ctx = toctx(L, 1);
    const char *s;
    switch (kmod_validate_resources(ctx)) {
    case KMOD_RESOURCES_OK:            s = "ok";       break;
    case KMOD_RESOURCES_MUST_RELOAD:   s = "reload";   break;
    case KMOD_RESOURCES_MUST_RECREATE: s = "recreate"; break;
    }
    lua_pushstring(L, s);
    return 1;
}

#define CONFIG_FOR_FUNCTION(name)                                       \
    static int ctx_config_ ## name(lua_State *L)                        \
    {                                                                   \
        if (lua_gettop(L) == 1) {                                       \
            struct kmod_ctx *ctx = toctx(L, 1);                         \
            lua_pushcfunction(L, ctx_config_ ## name);                  \
            *newconfig(L) = kmod_config_get_ ## name(ctx);              \
            return 2;                                                   \
        } else {                                                        \
            struct kmod_config_iter *iter = toconfig(L, 1);             \
            if (!kmod_config_iter_next(iter)) {                         \
                lua_pushnil(L);                                         \
                return 1;                                               \
            }                                                           \
            lua_pushstring(L, kmod_config_iter_get_key(iter));          \
            lua_pushstring(L, kmod_config_iter_get_value(iter));        \
            return 2;                                                   \
        }                                                               \
    }

CONFIG_FOR_FUNCTION(blacklists)
CONFIG_FOR_FUNCTION(install_commands)
CONFIG_FOR_FUNCTION(remove_commands)
CONFIG_FOR_FUNCTION(aliases)
CONFIG_FOR_FUNCTION(options)
CONFIG_FOR_FUNCTION(softdeps)

#undef CONFIG_FOR_FUNCTION

static int ctx_module_from_name(lua_State *L)
{
    struct kmod_ctx *ctx = toctx(L, 1);
    const char *name = luaL_checkstring(L, 2);
    struct kmod_module **mod = newmodule(L);
    int err = kmod_module_new_from_name(ctx, name, mod);
    if (err < 0)
        return kmod_error(L, -err);
    return 1;
}

static int ctx_module_from_path(lua_State *L)
{
    struct kmod_ctx *ctx = toctx(L, 1);
    const char *path = luaL_checkstring(L, 2);
    struct kmod_module **mod = newmodule(L);
    int err = kmod_module_new_from_path(ctx, path, mod);
    if (err < 0)
        return kmod_error(L, -err);
    return 1;
}

static int ctx_module_from_name_lookup(lua_State *L)
{
    struct kmod_ctx *ctx = toctx(L, 1);
    const char *modname = luaL_checkstring(L, 2);
    struct kmod_module **mod = newmodule(L);
    int err = kmod_module_new_from_name_lookup(ctx, modname, mod);
    if (err < 0)
        return kmod_error(L, -err);
    return 1;
}

static int ctx_modules_from_lookup(lua_State *L)
{
    struct list *list;

    if (lua_gettop(L) == 1) {
        /* 'for' start */
        struct kmod_ctx *ctx = toctx(L, 1);
        const char *alias = luaL_checkstring(L, 2);
        int err;

        lua_pushcfunction(L, ctx_modules_from_lookup);
        list = newlist(L, METH_KMOD_LIST_MODULE);

        err = kmod_module_new_from_lookup(ctx, alias, &list->head);
        if (err < 0)
            return kmod_error(L, -err);

        list->list = list->head;
        return 2;
    } else {
        /* 'for' step */
        list = (struct list *)lua_touserdata(L, 1);
        if (list->list == NULL) {
            lua_pushnil(L);
            return 1;
        }
        *newmodule(L) = kmod_module_get_module(list->list);
        list->list = kmod_list_next(list->head, list->list);
        return 1;
    }
}

static int ctx_modules_from_loaded(lua_State *L)
{
    struct list *list;

    if (lua_gettop(L) == 1) {
        /* 'for' start */
        struct kmod_ctx *ctx = toctx(L, 1);
        int err;

        lua_pushcfunction(L, ctx_modules_from_loaded);  /* generator */
        list = newlist(L, METH_KMOD_LIST_MODULE);       /* state */

        err = kmod_module_new_from_loaded(ctx, &list->head);
        if (err < 0)
            return kmod_error(L, -err);     /* XXX: luaL_argerror ? */

        list->list = list->head;
        return 2;
    } else {
        /* 'for' step */
        list = (struct list *)lua_touserdata(L, 1);
        if (list->list == NULL) {
            lua_pushnil(L);
            return 1;
        }
        *newmodule(L) = kmod_module_get_module(list->list);
        list->list = kmod_list_next(list->head, list->list);
        return 1;
    }
}

/*
static int ctx_module_apply_filter(lua_State *L)
{
    static const char *const opts[] = { "blacklist", "builtin", NULL };
    static enum kmod_filter optsfilter[] = {
        KMOD_FILTER_BLACKLIST,
        KMOD_FILTER_BUILTIN
    };
    struct kmodctx *ctx = tokmodctx(L, 1);
    struct kmodlist *input = tokmodlist(L, 2);
    int o = luaL_checkoption(L, 3, "blacklist", opts);
    struct kmod_list *output = NULL;
    int err = kmod_module_apply_filter(ctx->ctx, optsfilter[o],
                                       input->list, &output);
    if (err < 0)
        return kmod_error(L, -err);
    return list_new(L, output);
}
*/

static const luaL_Reg ctx_meth[] = {
    { "unref",                   ctx_unref                   },
    { "__gc",                    ctx_unref                   },
    { "dirname",                 ctx_dirname                 },
    { "load_resources",          ctx_load_resources          },
    { "unload_resources",        ctx_unload_resources        },
    { "validate_resources",      ctx_validate_resources      },
    { "config_blacklists",       ctx_config_blacklists       },
    { "config_install_commands", ctx_config_install_commands },
    { "config_remove_commands",  ctx_config_remove_commands  },
    { "config_aliases",          ctx_config_aliases          },
    { "config_options",          ctx_config_options          },
    { "config_softdeps",         ctx_config_softdeps         },
    { "module_from_name",        ctx_module_from_name        },
    { "module_from_path",        ctx_module_from_path        },
    { "module_from_name_lookup", ctx_module_from_name_lookup },
    { "modules_from_lookup",     ctx_modules_from_lookup     },
    { "modules_from_loaded",     ctx_modules_from_loaded     },
    /*
    { "module_apply_filter",     ctx_module_apply_filter     },
    */
    { NULL, NULL }
};

/******************************** config ********************************/

static int config_iter_free(lua_State *L)
{
    struct kmod_config_iter *iter = toconfig(L, 1);
    if (iter)
        kmod_config_iter_free_iter(iter);
    return 0;
}

static const luaL_Reg config_meth[] = {
    { "__gc", config_iter_free },
    { NULL, NULL }
};

/******************************** module ********************************/

static int module_unref(lua_State *L)
{
    struct kmod_module *mod = tomodule(L, 1);
    kmod_module_unref(mod);
    return 0;
}

#define METH_MODULE_DEF(name)                           \
    static int module_ ## name(lua_State *L)            \
    {                                                   \
        struct kmod_module *mod = tomodule(L, 1);       \
        const char *s = kmod_module_get_ ## name(mod);  \
        lua_pushstring(L, s);                           \
        return 1;                                       \
    }

METH_MODULE_DEF(name)
METH_MODULE_DEF(path)
METH_MODULE_DEF(options)
METH_MODULE_DEF(install_commands)
METH_MODULE_DEF(remove_commands)

#undef METH_MODULE_DEF

static int module_insert(lua_State *L)
{
    static const struct cflag_opt opts[] = {
        { "force", KMOD_INSERT_FORCE_VERMAGIC | KMOD_INSERT_FORCE_MODVERSION },
        { "force_vermagic",   KMOD_INSERT_FORCE_VERMAGIC   },
        { "force_modversion", KMOD_INSERT_FORCE_MODVERSION },
        { NULL, 0 }
    };
    struct kmod_module *mod = tomodule(L, 1);
    unsigned int flags = tocflags(L, 2, opts, 0);
    const char *options = luaL_optstring(L, 3, NULL);
    int err = kmod_module_insert_module(mod, flags, options);
    if (err < 0)
        return kmod_error(L, -err);
    lua_pushboolean(L, 1);
    return 1;
}

static int module_remove(lua_State *L)
{
    static const struct cflag_opt opts[] = {
        { "force",  KMOD_REMOVE_FORCE  },
        { "nowait", KMOD_REMOVE_NOWAIT },
        { "nolog",  KMOD_REMOVE_NOLOG  },
        { NULL, 0 }
    };
    struct kmod_module *mod = tomodule(L, 1);
    unsigned int flags = tocflags(L, 2, opts, 0);
    int err = kmod_module_remove_module(mod, flags);
    if (err < 0)
        return kmod_error(L, -err);
    lua_pushboolean(L, 1);
    return 1;
}

static int
run_install(struct kmod_module *mod, const char *cmdline, void *data)
{
    return 0;
}

static void
print_action(struct kmod_module *mod, bool install, const char *options)
{
}

static int module_probe_insert(lua_State *L)
{
    static const struct cflag_opt opts[] = {
        { "force",  KMOD_PROBE_FORCE_VERMAGIC | KMOD_PROBE_FORCE_MODVERSION },
        { "ignore", KMOD_PROBE_IGNORE_COMMAND | KMOD_PROBE_IGNORE_LOADED    },
        { "dry_run",          KMOD_PROBE_DRY_RUN          },
        { "fail_on_loaded",   KMOD_PROBE_FAIL_ON_LOADED   },
        { "force_vermagic",   KMOD_PROBE_FORCE_VERMAGIC   },
        { "force_modversion", KMOD_PROBE_FORCE_MODVERSION },
        { "ignore_command",   KMOD_PROBE_IGNORE_COMMAND   },
        { "ignore_loaded",    KMOD_PROBE_IGNORE_LOADED    },
        { NULL, 0 }
    };
    struct kmod_module *mod = tomodule(L, 1);
    unsigned int flags = tocflags(L, 2, opts, 0);
    const char *options = luaL_optstring(L, 3, NULL);
    int err = kmod_module_probe_insert_module(mod, flags, options,
                                        run_install, NULL, print_action);
    if (err < 0)
        return kmod_error(L, -err);
    lua_pushboolean(L, 1);
    return 1;
}

static int module_initstate(lua_State *L)
{
    struct kmod_module *mod = tomodule(L, 1);
    int state = kmod_module_get_initstate(mod);
    const char *s = kmod_module_initstate_str(state);
    if (s == NULL)
        s = "unknown";
    lua_pushstring(L, s);
    return 1;
}

static int module_refcnt(lua_State *L)
{
    struct kmod_module *mod = tomodule(L, 1);
    lua_pushinteger(L, (lua_Integer)kmod_module_get_refcnt(mod));
    return 1;
}

static int module_size(lua_State *L)
{
    struct kmod_module *mod = tomodule(L, 1);
    lua_pushinteger(L, (lua_Integer)kmod_module_get_size(mod));
    return 1;
}

/*
static int module_softdeps(lua_State *L)
{
    struct kmodmodule *m = tomodule(L, 1);
    struct kmod_list *pre = NULL, *post = NULL;
    int err = kmod_module_get_softdeps(m->mod, &pre, &post);
    if (err < 0)
        return kmod_error(L, -err);
    return list_new(L, pre) + list_new(L, post);
}
*/

#define MODULE_FOR_FUNCTION(name, tname)                                    \
    static int module_ ## name(lua_State *L)                                \
    {                                                                       \
        struct list *list;                                                  \
        if (lua_gettop(L) == 1) {                                           \
            /* 'for' start */                                               \
            struct kmod_module *mod = tomodule(L, 1);                       \
            lua_pushcfunction(L, module_ ## name);                          \
            list = newlist(L, METH_KMOD_LIST_ ## tname);                    \
            list->head = kmod_module_get_ ## name(mod);                     \
            list->list = list->head;                                        \
            return 2;                                                       \
        } else {                                                            \
            /* 'for' step */                                                \
            list = (struct list *)lua_touserdata(L, 1);                     \
            if (list->list == NULL) {                                       \
                lua_pushnil(L);                                             \
                return 1;                                                   \
            }                                                               \
            VARS_ ## name(L, list);                                         \
        }                                                                   \
    }

#define VARS_module(L, list)                                                \
    do {                                                                    \
        *newmodule(L) = kmod_module_get_module(list->list);                 \
        list->list = kmod_list_next(list->head, list->list);                \
        return 1;                                                           \
    } while (0)

#define VARS_dependencies(L, list)  VARS_module(L, list)
#define VARS_holders(L, list)       VARS_module(L, list)

#define VARS_sections(L, list)                                              \
    do {                                                                    \
        unsigned long addr = kmod_module_section_get_address(list->list);   \
        lua_pushstring(L, kmod_module_section_get_name(list->list));        \
        lua_pushnumber(L, (lua_Number)addr);                                \
        list->list = kmod_list_next(list->head, list->list);                \
        return 2;                                                           \
    } while (0)

MODULE_FOR_FUNCTION(dependencies, MODULE)
MODULE_FOR_FUNCTION(holders, MODULE)
MODULE_FOR_FUNCTION(sections, MOD_SECTION)

#undef MODULE_FOR_FUNCTION

#define MODULE_FOR_FUNCTION(name, fname, tname)                             \
    static int module_ ## name(lua_State *L)                                \
    {                                                                       \
        struct list *list;                                                  \
        if (lua_gettop(L) == 1) {                                           \
            /* 'for' start */                                               \
            struct kmod_module *mod = tomodule(L, 1);                       \
            int err;                                                        \
            lua_pushcfunction(L, module_ ## name);                          \
            list = newlist(L, METH_KMOD_LIST_ ## tname);                    \
            err = kmod_module_get_ ## fname(mod, &list->head);              \
            if (err < 0)                                                    \
                return kmod_error(L, -err);                                 \
            list->list = list->head;                                        \
            return 2;                                                       \
        } else {                                                            \
            /* 'for' step */                                                \
            list = (struct list *)lua_touserdata(L, 1);                     \
            if (list->list == NULL) {                                       \
                lua_pushnil(L);                                             \
                return 1;                                                   \
            }                                                               \
            VARS_ ## name(L, list);                                         \
        }                                                                   \
    }

#define VARS_infos(L, list)                                                 \
    do {                                                                    \
        const char *s;                                                      \
        size_t len;                                                         \
        lua_pushstring(L, kmod_module_info_get_key(list->list));            \
        s = kmod_module_info_get_value_n(list->list, &len);                 \
        lua_pushlstring(L, s, len);                                         \
        list->list = kmod_list_next(list->head, list->list);                \
        return 2;                                                           \
    } while (0)

#define VARS_versions(L, list)                                              \
    do {                                                                    \
        lua_pushstring(L, kmod_module_version_get_symbol(list->list));      \
        lua_pushnumber(L, (lua_Number)kmod_module_version_get_crc(list->list));\
        list->list = kmod_list_next(list->head, list->list);                \
        return 2;                                                           \
    } while (0)

#define VARS_symbols(L, list)                                               \
    do {                                                                    \
        lua_pushstring(L, kmod_module_symbol_get_symbol(list->list));       \
        lua_pushnumber(L, (lua_Number)kmod_module_symbol_get_crc(list->list));\
        list->list = kmod_list_next(list->head, list->list);                \
        return 2;                                                           \
    } while (0)

#define VARS_dep_symbols(L, list)                                           \
    do {                                                                    \
        const char *s = "unknown";                                          \
        lua_pushstring(L,                                                   \
            kmod_module_dependency_symbol_get_symbol(list->list));          \
        lua_pushnumber(L,                                                   \
            (lua_Number)kmod_module_dependency_symbol_get_crc(list->list)); \
        switch (kmod_module_dependency_symbol_get_bind(list->list)) {       \
        case KMOD_SYMBOL_NONE:   s = "none";   break;                       \
        case KMOD_SYMBOL_LOCAL:  s = "local";  break;                       \
        case KMOD_SYMBOL_GLOBAL: s = "global"; break;                       \
        case KMOD_SYMBOL_WEAK:   s = "weak";   break;                       \
        case KMOD_SYMBOL_UNDEF:  s = "undef";  break;                       \
        };                                                                  \
        lua_pushstring(L, s);                                               \
        list->list = kmod_list_next(list->head, list->list);                \
        return 3;                                                           \
    } while (0)

MODULE_FOR_FUNCTION(infos, info, MOD_INFO)
MODULE_FOR_FUNCTION(versions, versions, MOD_VERSION)
MODULE_FOR_FUNCTION(symbols, symbols, MOD_SYMBOL)
MODULE_FOR_FUNCTION(dep_symbols, dependency_symbols, MOD_DEP_SYMBOL)

#undef MODULE_FOR_FUNCTION


struct module_signature {
	uint8_t		algo;		/* Public-key crypto algorithm [0] */
	uint8_t		hash;		/* Digest algorithm [0] */
	uint8_t		id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	uint8_t		signer_len;	/* Length of signer's name [0] */
	uint8_t		key_id_len;	/* Length of key identifier [0] */
	uint8_t		__pad[3];
	uint32_t	sig_len;	/* Length of signature data */
};

#define PKEY_ID_PKCS7 2
#define SIG_MAGIC "~Module signature appended~\n"

#define get_unaligned(ptr)                  \
    ({                                      \
        struct __attribute__((packed)) {    \
        typeof(*(ptr)) __v;                 \
        } *__p = (typeof(__p)) (ptr);       \
        __p->__v;                           \
    })


/*
static STACK_OF(X509) *read_certs(const char *cert_file)
{
    STACK_OF(X509) *certs = sk_X509_new_null();
    BIO *bio = BIO_new_file(cert_file, "rb");
    STACK_OF(X509_INFO) *xis = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
    int i;

    for (i = 0; i < sk_X509_INFO_num(xis); i++) {
        xi = sk_X509_INFO_value(xis, i);
        if (xi->x509 != NULL) {
            sk_X509_push(certs, xi->x509);
            xi->x509 = NULL;
        }
    }
    sk_X509_INFO_pop_free(xis, X509_INFO_free);
    BIO_free(bio);
    return certs;
}
*/

static EVP_PKEY *read_private_key(const char *privkey_file)
{
    EVP_PKEY *privkey;
    BIO *b;

    b = BIO_new_file(privkey_file, "rb");
    if (b == NULL)
        return NULL;

    privkey = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    return privkey;
}

static X509 *read_x509(const char *x509_file)
{
    unsigned char buf[2];
    X509 *x509 = NULL;
    BIO *b;

    b = BIO_new_file(x509_file, "rb");
    if (b == NULL)
        return NULL;

    do {
        if (BIO_read(b, buf, 2) != 2)
            break;

        if (BIO_reset(b) != 0)
            break;

        if (buf[0] == 0x30 && buf[1] >= 0x81 && buf[1] <= 0x84)
            x509 = d2i_X509_bio(b, NULL);
        else
            x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);
    } while (0);

    BIO_free(b);
    return x509;
}

static X509_STORE *read_x509_store(const char *cert_file)
{
    BIO *bio;
    X509_STORE *store;
    X509 *cert;

    if ((bio = BIO_new_file(cert_file, "r")) == NULL)
        return NULL;

    cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio);
    if (cert == NULL)
        return NULL;

    if ((store = X509_STORE_new()) == NULL) {
        X509_free(cert);
        return NULL;
    }

    if (X509_STORE_add_cert(store, cert))
        return store;

    X509_STORE_free(store);
    X509_free(cert);
    return NULL;
}

static CMS_ContentInfo *cms_sign_file(const char *hash_algo,
            const char *privkey_file, const char *x509_file, const char *file)
{
    const unsigned int flags = CMS_NOCERTS | CMS_BINARY;
    const EVP_MD *md;
    EVP_PKEY *privkey;
    X509 *x509;
    BIO *b;
    CMS_ContentInfo *cms;
    int err;

    if ((md = EVP_get_digestbyname(hash_algo)) == NULL)
        return NULL;
    if ((privkey = read_private_key(privkey_file)) == NULL)
        return NULL;

    if ((x509 = read_x509(x509_file)) == NULL)
        goto err_free_pkey;

    if ((b = BIO_new_file(file, "rb")) == NULL)
        goto err_free_x509;

    cms = CMS_sign(NULL, NULL, NULL, NULL,
                    flags | CMS_PARTIAL | CMS_DETACHED | CMS_STREAM);
    if (cms == NULL)
        goto err_free_bio;

    if (!CMS_add1_signer(cms, x509, privkey, md,
                    flags | CMS_NOSMIMECAP | CMS_NOATTR))
        goto err_free_cms;

    if (CMS_final(cms, b, NULL, flags) < 0)
        goto err_free_cms;

    BIO_free(b);
    X509_free(x509);
    EVP_PKEY_free(privkey);
    return cms;

err_free_cms:
    CMS_ContentInfo_free(cms);
err_free_bio:
    BIO_free(b);
err_free_x509:
    X509_free(x509);
err_free_pkey:
    EVP_PKEY_free(privkey);
    return NULL;
}

static int kmod_sign_file(CMS_ContentInfo *cms,
                          const char *srcfile, const char *dstfile)
{
    struct module_signature siginfo = { .id_type = PKEY_ID_PKCS7 };
    unsigned long msize, sigsize;
    unsigned char buffer[4096];
    BIO *bm, *bd;
    int n;
    int err = -EINVAL;

    if ((bm = BIO_new_file(srcfile, "rb")) == NULL)
        return -EINVAL;
    if ((bd = BIO_new_file(dstfile, "wb")) == NULL)
        goto err_free_bm;

    while ((n = BIO_read(bm, buffer, sizeof(buffer))) > 0) {
        if ((n = BIO_write(bd, buffer, n)) < 0)
            break;
    }
    if (n < 0)
        goto err_free_bd;

    err = -EBUSY;
    msize = BIO_number_written(bd);
    if (i2d_CMS_bio_stream(bd, cms, NULL, 0) < 0)
        goto err_free_bd;
    sigsize = BIO_number_written(bd) - msize;
    siginfo.sig_len = htonl(sigsize);
    if (BIO_write(bd, &siginfo, sizeof(siginfo)) < 0)
        goto err_free_bd;
    if (BIO_write(bd, SIG_MAGIC, sizeof(SIG_MAGIC) - 1) < 0)
        goto err_free_bd;

    err = 0;

err_free_bd:
    BIO_free(bd);
err_free_bm:
    BIO_free(bm);
    return err;
}

static int do_kmod_sign(const char *module_file, const char *hash_algo,
                        const char *privkey_file, const char *x509_file,
                        const char *dst_file, int save_sig)
{
    CMS_ContentInfo *cms;
    int err;

    cms = cms_sign_file(hash_algo, privkey_file, x509_file, module_file);
    if (cms == NULL)
        return -EINVAL;

    if (save_sig) {
        BIO *bd;

        err = -EFAULT;
        if ((bd = BIO_new_file(dst_file, "wb")) != NULL) {
            if (i2d_CMS_bio_stream(bd, cms, NULL, 0) >= 0)
                err = 0;

            BIO_free(bd);
        }
    } else {
        if (!dst_file || dst_file == module_file) {
            char *dest;

            err = -ENOMEM;
            if (asprintf(&dest, "%s.~signed~", module_file) >= 0) {
                err = kmod_sign_file(cms, module_file, dest);
                if (err >= 0) {
                    err = -ENOENT;
                    if (rename(dest, module_file) >= 0)
                        err = 0;
                }

                free(dest);
            }
        } else {
            err = kmod_sign_file(cms, module_file, dst_file);
        }
    }

    CMS_ContentInfo_free(cms);
    return err;
}

static int module_sign(lua_State *L)
{
    struct kmod_module *mod = tomodule(L, 1);
    const char *hash_algo = luaL_checkstring(L, 2);
    const char *privkey_file = luaL_checkstring(L, 3);
    const char *x509_file = luaL_checkstring(L, 4);
    const char *dst_file = luaL_optstring(L, 5, NULL);
    int save_sig = lua_toboolean(L, 6);
    const char *path = kmod_module_get_path(mod);
    int err;

    err = do_kmod_sign(path, hash_algo, privkey_file,
                       x509_file, dst_file, save_sig);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    } else {
        lua_pushboolean(L, 1);
        return 1;
    }
}

/* TODO FIXME: verify failed */
static int pkcs7_verify(BIO *in, BIO *sig, const char *cert_file)
{
    X509_STORE *store;
    PKCS7 *p7;
    int err;

    if ((store = read_x509_store(cert_file)) == NULL)
        return -ENOENT;

    err = -EBADMSG;
    p7 = d2i_PKCS7_bio(sig, NULL);
    if (p7 == NULL)
        goto err_free_store;

    err = -EBADF;
    if (PKCS7_verify(p7, NULL, store, in, NULL, PKCS7_NOVERIFY))
        err = 0;

    PKCS7_free(p7);
err_free_store:
    X509_STORE_free(store);
    return err;
}

static int do_verify_sig(const char *filename,
                         const char *cert_file, const char *sig_file)
{
    BIO *in, *sig;
    int err = -EINVAL;

    if ((in = BIO_new_file(filename, "rb")) == NULL)
        return -EINVAL;
    if ((sig = BIO_new_file(sig_file, "rb")) == NULL)
        goto err_free_in;

    err = pkcs7_verify(in, sig, cert_file);

    BIO_free(sig);
err_free_in:
    BIO_free(in);
    return err;
}

/*
 * A signed module has the following layout:
 *
 * [ module                  ]
 * [ signer's name           ]
 * [ key identifier          ]
 * [ signature data          ]
 * [ struct module_signature ]
 * [ SIG_MAGIC               ]
 */
static int do_kmod_map(const char *filename, unsigned char **p, off_t *lenp,
                       unsigned char **sigp, size_t *siglenp)
{
    const struct module_signature *sig;
    unsigned char *mem;
    struct stat st;
    off_t size;
    int siglen;
    int fd;
    int err = -EINVAL;

    fd = open(filename, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;

    if (fstat(fd, &st) < 0)
        goto err_close_fd;

    mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED)
        goto err_close_fd;

    err = -ERANGE;
    size = st.st_size;
    if (size < ((off_t)sizeof(SIG_MAGIC) - 1 + sizeof(*sig)))
        goto err_unmap;

    err = -EBADMSG;
    size -= (sizeof(SIG_MAGIC) - 1);
    if (memcmp(mem + size, SIG_MAGIC, sizeof(SIG_MAGIC) - 1) != 0)
        goto err_unmap;

    size -= sizeof(struct module_signature);
    sig = (struct module_signature *)(mem + size);
    siglen = be32toh(get_unaligned(&sig->sig_len));
    if (siglen == 0 ||
        (off_t)(siglen + sig->signer_len + sig->key_id_len) > size)
        goto err_unmap;

    size -= siglen;

    *p = mem;
    *lenp = st.st_size;
    *sigp = mem + size;
    *siglenp = siglen;

    close(fd);
    return 0;

err_unmap:
    munmap((void *)mem, st.st_size);
err_close_fd:
    close(fd);
    return err;
}

static int do_verify_kmod(const char *filename, const char *cert_file)
{
    unsigned char *mem, *sigraw;
    off_t len;
    size_t siglen;
    BIO *in, *sig;
    int err;

    err = do_kmod_map(filename, &mem, &len, &sigraw, &siglen);
    if (err < 0)
        return err;

    in = BIO_new_mem_buf(mem, sigraw - mem);
    if (in == NULL)
        goto err_unmap;
    sig = BIO_new_mem_buf(sigraw, siglen);
    if (sig == NULL)
        goto err_free_in;

    err = pkcs7_verify(in, sig, cert_file);

    BIO_free(sig);
err_free_in:
    BIO_free(in);
err_unmap:
    munmap((void *)mem, len);
    return err;
}

static int do_verify(lua_State *L, const char *pathname,
                     const char *cert_file, const char *sig_file)
{
    int err;

    if (sig_file)
        err = do_verify_sig(pathname, cert_file, sig_file);
    else
        err = do_verify_kmod(pathname, cert_file);

    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    } else {
        lua_pushboolean(L, 1);
        return 1;
    }
}

static int module_verify(lua_State *L)
{
    struct kmod_module *mod = tomodule(L, 1);
    const char *cert_file = luaL_checkstring(L, 2);
    const char *sig_file = luaL_optstring(L, 3, NULL);
    const char *path = kmod_module_get_path(mod);
    return do_verify(L, path, cert_file, sig_file);
}

static int do_sigraw(lua_State *L, const char *pathname, int rawko)
{
    unsigned char *mem, *sig;
    off_t len;
    size_t siglen;
    int nret;
    int err;

    err = do_kmod_map(pathname, &mem, &len, &sig, &siglen);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    }

    lua_pushlstring(L, sig, siglen);
    nret = 1;
    if (rawko) {
        lua_pushlstring(L, mem, sig - mem);
        nret++;
    }
    munmap(mem, len);
    return nret;
}

static int module_sigraw(lua_State *L)
{
    struct kmod_module *mod = tomodule(L, 1);
    int rawko = lua_toboolean(L, 2);
    const char *path = kmod_module_get_path(mod);
    return do_sigraw(L, path, rawko);
}

static const luaL_Reg module_meth[] = {
    { "unref",              module_unref              },
    { "__gc",               module_unref              },
    { "name",               module_name               },
    { "path",               module_path               },
    { "options",            module_options            },
    { "install_commands",   module_install_commands   },
    { "remove_commands",    module_remove_commands    },
    { "insert",             module_insert             },
    { "remove",             module_remove             },
    { "probe_insert",       module_probe_insert       },
    { "initstate",          module_initstate          },
    { "refcnt",             module_refcnt             },
    { "size",               module_size               },
    /*
    { "softdeps",           module_softdeps           },
    */
    { "dependencies",       module_dependencies       },
    { "holders",            module_holders            },
    { "sections",           module_sections           },
    { "infos",              module_infos              },
    { "versions",           module_versions           },
    { "symbols",            module_symbols            },
    { "dep_symbols",        module_dep_symbols        },
    { "sign",               module_sign               },
    { "verify",             module_verify             },
    { "sigraw",             module_sigraw             },
    { NULL, NULL }
};

/******************************** list ********************************/

#define LIST_GC_DEF(name, fn, tname)                                \
    static int list_ ## name ## _free(lua_State *L)                 \
    {                                                               \
        struct list *list = tolist(L, 1, METH_KMOD_LIST_ ## tname); \
        kmod_module_ ## fn ## _list(list->head);                    \
        return 0;                                                   \
    }                                                               \
    static const luaL_Reg list_meth_ ## name[] = {                  \
        { "__gc", list_ ## name ## _free },                         \
        { NULL, NULL }                                              \
    }

LIST_GC_DEF(modules, unref, MODULE);
LIST_GC_DEF(mod_sections, section_free, MOD_SECTION);
LIST_GC_DEF(mod_infos, info_free, MOD_INFO);
LIST_GC_DEF(mod_versions, versions_free, MOD_VERSION);
LIST_GC_DEF(mod_symbols, symbols_free, MOD_SYMBOL);
LIST_GC_DEF(mod_dep_symbols, dependency_symbols_free, MOD_DEP_SYMBOL);

/******************************** kmod ********************************/

static int ctx_new(lua_State *L)
{
    const char *dirname = luaL_optstring(L, 1, NULL);
    struct kmod_ctx **pctx;

    pctx = newctx(L);
    *pctx = kmod_new(dirname, NULL);
    if (*pctx == NULL)
        lua_pushnil(L);
    return 1;
}

/*
static int openssl_error(lua_State *L, const char *err)
{
    const char *file;
    char buffer[120];
    int e, line, nres = 2;
    lua_pushnil(L);
    lua_pushstring(L, err);
    if (ERR_peek_error() == 0)
        return nres;
    while (e = ERR_get_error_line(&file, &line)) {
        ERR_error_string(e, buffer);
        lua_pushfstring(L, "%s: %s:%d", buffer, file, line);
        nres++;
    }
    return nres;
}

static int openssl_error(lua_State *L)
{
    char buffer[256];
    unsigned long e = ERR_get_error();
    lua_pushnil(L);
    lua_pushinteger(L, (lua_Integer)e);
    lua_pushstring(L, ERR_error_string_n(e, buffer, sizeof(buffer)));
    return 3;
}
*/

/*
local ok = sign(modfile, "sm3", privkey, x509)
local ok = sign(modfile, "sm3", privkey, x509, dstfile)
local ok = sign(modfile, "sm3", privkey, x509, sigfile, true)

local ok = mod:sign("sm3", privkey, x509)
local ok = mod:sign("sm3", privkey, x509, dstfile)
local ok = mod:sign("sm3", privkey, x509, sigfile, true)

local ok = verify(modfile, cert)
local ok = verify(modfile, cert, sigfile)

local ok = mod:verify(cert)
local ok = mod:verify(cert, sigfile)
*/

static int kmod_sign(lua_State *L)
{
    const char *module_file = luaL_checkstring(L, 1);
    const char *hash_algo = luaL_checkstring(L, 2);
    const char *privkey_file = luaL_checkstring(L, 3);
    const char *x509_file = luaL_checkstring(L, 4);
    const char *dst_file = luaL_optstring(L, 5, NULL);
    int save_sig = lua_toboolean(L, 6);
    int err;

    err = do_kmod_sign(module_file, hash_algo, privkey_file,
                       x509_file, dst_file, save_sig);
    if (err < 0) {
        lua_pushnil(L);
        lua_pushinteger(L, -err);
        return 2;
    } else {
        lua_pushboolean(L, 1);
        return 1;
    }
}

static int kmod_verify(lua_State *L)
{
    const char *pathname = luaL_checkstring(L, 1);
    const char *cert_file = luaL_checkstring(L, 2);
    const char *sig_file = luaL_optstring(L, 3, NULL);
    return do_verify(L, pathname, cert_file, sig_file);
}

static int kmod_sigraw(lua_State *L)
{
    const char *pathname = luaL_checkstring(L, 1);
    int rawko = lua_toboolean(L, 2);
    return do_sigraw(L, pathname, rawko);
}

static const luaL_Reg kmodlib[] = {
    { "ctx_new", ctx_new      },
    { "sign",    kmod_sign    },
    { "verify",  kmod_verify  },
    { "sigraw",  kmod_sigraw  },
    { NULL, NULL }
};

LUALIB_API int luaopen_kmod(lua_State *L)
{
    luaL_newlib(L, kmodlib);

    createmeta(L, METH_KMOD_CTX, ctx_meth);
    createmeta(L, METH_KMOD_MODULE, module_meth);
    createmeta(L, METH_KMOD_CONFIG, config_meth);

#define LIST_createmeta(name, tname)    \
    createmeta(L, METH_KMOD_LIST_ ## tname, list_meth_ ## name)

    LIST_createmeta(modules, MODULE);
    LIST_createmeta(mod_sections, MOD_SECTION);
    LIST_createmeta(mod_infos, MOD_INFO);
    LIST_createmeta(mod_versions, MOD_VERSION);
    LIST_createmeta(mod_symbols, MOD_SYMBOL);
    LIST_createmeta(mod_dep_symbols, MOD_DEP_SYMBOL);

    return 1;
}
