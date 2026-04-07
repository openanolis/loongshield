#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include <rpm/rpmdb.h>
#include <rpm/rpmts.h>
#include <rpm/rpmtd.h>
#include <rpm/rpmfi.h>
#include <rpm/header.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmlib.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <compat-5.3.h>
#include "luauxlib.h"


#define METH_RPM_TS         "meth_rpm_ts"
#define METH_RPM_FI         "meth_rpm_fi"
#define METH_RPM_HEADER     "meth_rpm_header"
#define METH_RPM_MI         "meth_rpm_mi"

#define newrpmts(L)         (rpmts *)newcptr((L), METH_RPM_TS)
#define newrpmfi(L)         (rpmfi *)newcptr((L), METH_RPM_FI)
#define newrpmheader(L)     (Header *)newcptr((L), METH_RPM_HEADER)
#define newrpmmi(L)         (rpmdbMatchIterator *)newcptr((L), METH_RPM_MI)

#define torpmtsp(L, idx)    (rpmts *)luaL_checkudata((L), (idx), METH_RPM_TS)
#define torpmfip(L, idx)    (rpmfi *)luaL_checkudata((L), (idx), METH_RPM_FI)
#define torpmheaderp(L, idx)    \
    (Header *)luaL_checkudata((L), (idx), METH_RPM_HEADER)
#define torpmmip(L, idx)        \
    (rpmdbMatchIterator *)luaL_checkudata((L), (idx), METH_RPM_MI)

#define torpmts(L, idx)         (*torpmtsp(L, idx))
#define torpmfi(L, idx)         (*torpmfip(L, idx))
#define torpmheader(L, idx)     (*torpmheaderp(L, idx))
#define torpmmi(L, idx)         (*torpmmip(L, idx))

/********************************** mi ***********************************/

static int mi_free(lua_State *L)
{
    rpmdbMatchIterator *mip = torpmmip(L, 1);
    if (*mip) {
        rpmdbFreeIterator(*mip);
        *mip = NULL;
    }
    return 0;
}

static const luaL_Reg rpmmi_meth[] = {
    { "__gc",       mi_free     },
    { NULL, NULL }
};

/********************************** fi ***********************************/

static int fi_free(lua_State *L)
{
    rpmfi *fip = torpmfip(L, 1);
    if (*fip) {
        rpmfiFree(*fip);
        *fip = NULL;
    }
    return 0;
}

static int fi_index(lua_State *L)
{
    rpmfi fi = torpmfi(L, 1);
    lua_pushinteger(L, rpmfiFX(fi));
    return 1;
}

static int fi_size(lua_State *L)
{
    rpmfi fi = torpmfi(L, 1);
    lua_pushinteger(L, (lua_Integer)rpmfiFSize(fi));
    return 1;
}

static int fi_count(lua_State *L)
{
    rpmfi fi = torpmfi(L, 1);
    lua_pushinteger(L, (lua_Integer)rpmfiFC(fi));
    return 1;
}

#define FI_DEF_STRING(name, apiname)                                        \
    static int fi_ ## name(lua_State *L)                                    \
    {                                                                       \
        rpmfi fi = torpmfi(L, 1);                                           \
        const char *s = rpmfi ## apiname(fi);                               \
        if (s == NULL)                                                      \
            return 0;                                                       \
        lua_pushstring(L, s);                                               \
        return 1;                                                           \
    }

FI_DEF_STRING(basename, BN)
FI_DEF_STRING(dirname,  DN)
FI_DEF_STRING(name,     FN)
FI_DEF_STRING(user,     FUser)
FI_DEF_STRING(group,    FGroup)

static int fi_digest(lua_State *L)
{
    rpmfi fi = torpmfi(L, 1);
    char *digest = rpmfiFDigestHex(fi, NULL);
    if (digest == NULL)
        return 0;
    lua_pushstring(L, digest);
    free(digest);
    return 1;
}

static int fi_flags(lua_State *L)
{
    rpmfi fi = torpmfi(L, 1);
    lua_pushinteger(L, (lua_Integer)rpmfiFFlags(fi));
    return 1;
}

static const luaL_Reg rpmfi_meth[] = {
    { "__gc",       fi_free     },
    { "index",      fi_index    },
    { "size",       fi_size     },
    { "count",      fi_count    },
    { "basename",   fi_basename },
    { "dirname",    fi_dirname  },
    { "name",       fi_name     },
    { "digest",     fi_digest   },
    { "flags",      fi_flags    },
    { "user",       fi_user     },
    { "group",      fi_group    },
    { NULL, NULL }
};

/******************************** header *********************************/

static int header_free(lua_State *L)
{
    /*
     * You do not need to free the Header returned by rpmdbNextIterator.
     * Also, the next call to rpmdbNextIterator will reset the Header.
     */
    /*
    Header *hp = torpmheaderp(L, 1);
    if (*hp) {
        headerFree(*hp);
        *hp = NULL;
    }
    */
    return 0;
}

#define HEADER_DEF_STRING(name, tagname)                                    \
    static int header_ ## name(lua_State *L)                                \
    {                                                                       \
        Header h = torpmheader(L, 1);                                       \
        struct rpmtd_s td;                                                  \
        const char *s;                                                      \
        int rc = headerGet(h, RPMTAG_ ## tagname, &td, HEADERGET_MINMEM);   \
        if (!rc)                                                            \
            return 0;                                                       \
        s = rpmtdGetString(&td);                                            \
        rpmtdFreeData(&td);                                                 \
        if (s == NULL)                                                      \
            return 0;                                                       \
        lua_pushstring(L, s);                                               \
        return 1;                                                           \
    }

HEADER_DEF_STRING(name,     NAME)
HEADER_DEF_STRING(version,  VERSION)
HEADER_DEF_STRING(release,  RELEASE)
HEADER_DEF_STRING(arch,     ARCH)
HEADER_DEF_STRING(vendor,   VENDOR)
HEADER_DEF_STRING(license,  LICENSE)
HEADER_DEF_STRING(packager, PACKAGER)
HEADER_DEF_STRING(url,      URL)

static int header_files_next(lua_State *L)
{
    rpmfi fi = torpmfi(L, 1);
    if (rpmfiNext(fi) == -1)
        return 0;
    lua_settop(L, 1);
    return 1;
}

static int header_files(lua_State *L)
{
    Header h = torpmheader(L, 1);
    rpmfi *fip;
    lua_pushcfunction(L, header_files_next);
    fip = newrpmfi(L);
    /* XXX: flag RPMFI_KEEPHEADER will reference header */
    *fip = rpmfiNew(NULL, h, RPMTAG_BASENAMES, RPMFI_KEEPHEADER);
    /* headerFree(h); */
    if (*fip == NULL)
        return 0;
    rpmfiInit(*fip, 0);
    return 2;
}

static const luaL_Reg rpmheader_meth[] = {
    { "__gc",       header_free     },
    { "name",       header_name     },
    { "version",    header_version  },
    { "release",    header_release  },
    { "arch",       header_arch     },
    { "vendor",     header_vendor   },
    { "license",    header_license  },
    { "packager",   header_packager },
    { "url",        header_url      },
    { "files",      header_files    },
    { NULL, NULL }
};

/********************************** ts ***********************************/

static int ts_free(lua_State *L)
{
    rpmts *tsp = torpmtsp(L, 1);
    if (*tsp) {
        rpmtsFree(*tsp);
        *tsp = NULL;
    }
    return 0;
}

static int ts_rootdir(lua_State *L)
{
    rpmts ts = torpmts(L, 1);
    if (lua_gettop(L) == 1) {
        const char *rootdir = rpmtsRootDir(ts);
        lua_pushstring(L, rootdir ? rootdir : "/");
    } else {
        const char *s = luaL_checkstring(L, 2);
        int rc = rpmtsSetRootDir(ts, s);
        if (rc == 0) {
            /* After setting root directory, open the database */
            rc = rpmtsOpenDB(ts, O_RDONLY);
            if (rc != 0) {
                luaL_error(L, "Failed to open RPM database after setting root (code %d)", rc);
            }
        }
        lua_pushboolean(L, rc == 0);
    }
    return 1;
}

static int ts_packages_next(lua_State *L)
{
    rpmdbMatchIterator *mip = torpmmip(L, lua_upvalueindex(1));
    Header *hp = newrpmheader(L);
    *hp = rpmdbNextIterator(*mip);
    if (*hp == NULL) {
        rpmdbFreeIterator(*mip);
        *mip = NULL;
        return 0;
    }
    return 1;
}

static int ts_packages(lua_State *L)
{
    rpmts ts = torpmts(L, 1);
    const char *key = luaL_optstring(L, 2, NULL);
    rpmdbMatchIterator *mip = newrpmmi(L);
    rpmDbiTagVal tag = (key == NULL) ? RPMDBI_PACKAGES : RPMDBI_NAME;
    size_t keylen = (key == NULL) ? 0 : strlen(key);

    *mip = rpmtsInitIterator(ts, tag, key, keylen);
    if (*mip == NULL)
        return 0;
    lua_pushcclosure(L, ts_packages_next, 1);
    return 1;
}

static const luaL_Reg rpmts_meth[] = {
    { "__gc",       ts_free     },
    { "rootdir",    ts_rootdir  },
    { "packages",   ts_packages },
    { NULL, NULL }
};

/********************************* main **********************************/

static int rpm_tscreate(lua_State *L)
{
    rpmts *tsp = newrpmts(L);
    /*
    rpmSetVerbosity(RPMLOG_DEBUG);
    */
    *tsp = rpmtsCreate();
    if (*tsp == NULL)
        return 0;

    /* Disable all signature and digest verification to avoid crashes in
     * pgpPubkeyFingerprint/rpmDigestInit when reading the database.
     * Since we're only reading an already-installed database, verification
     * is not necessary.
     */
    rpmtsSetVSFlags(*tsp, _RPMVSF_NODIGESTS | _RPMVSF_NOSIGNATURES);
    return 1;
}

static int rpm_readconfig(lua_State *L)
{
    const char *rcfile = luaL_optstring(L, 1, NULL);
    const char *target = luaL_optstring(L, 2, NULL);
    int rc = rpmReadConfigFiles(rcfile, target);
    if (rc != 0) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "rpmReadConfigFiles failed with code %d", rc);
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

static int rpm_initmacros(lua_State *L)
{
    const char *macrofiles = luaL_checkstring(L, 1);
    rpmInitMacros(NULL, macrofiles);
    return 0;
}

static int rpm_pushmacro(lua_State *L)
{
    const char *name = luaL_checkstring(L, 1);
    const char *body = luaL_checkstring(L, 2);
    /* XXX: RMIL_GLOBAL ? */
    int rc = rpmPushMacro(NULL, name, NULL, body, RMIL_CMDLINE);
    lua_pushboolean(L, rc == 0);
    return 1;
}

static int rpm_popmacro(lua_State *L)
{
    const char *name = luaL_checkstring(L, 1);
    int rc = rpmPopMacro(NULL, name);
    lua_pushboolean(L, rc == 0);
    return 1;
}

static int rpm_configdir(lua_State *L)
{
    lua_pushstring(L, rpmConfigDir());
    return 1;
}

static int rpm_getpath(lua_State *L)
{
    const char *s1 = luaL_checkstring(L, 1);
    const char *s2, *s3;
    const char *s = NULL;
    switch (lua_gettop(L)) {
    case 1:
        s = rpmGetPath(s1, NULL);
        break;
    case 2:
        s2 = luaL_checkstring(L, 2);
        s = rpmGetPath(s1, s2, NULL);
        break;
    case 3:
        s2 = luaL_checkstring(L, 2);
        s3 = luaL_checkstring(L, 3);
        s = rpmGetPath(s1, s2, s3, NULL);
        break;
    }
    if (s == NULL)
        return 0;
    lua_pushstring(L, s);
    free((void *)s);
    return 1;
}

static const luaL_Reg rpmlib[] = {
    { "tscreate",    rpm_tscreate    },
    { "readconfig",  rpm_readconfig  },
    { "initmacros",  rpm_initmacros  },
    { "pushmacro",   rpm_pushmacro   },
    { "popmacro",    rpm_popmacro    },
    { "configdir",   rpm_configdir   },
    { "getpath",     rpm_getpath     },
    { NULL, NULL }
};


LUALIB_API int luaopen_lrpm(lua_State *L)
{
    luaL_newlib(L, rpmlib);

    createmeta(L, METH_RPM_TS, rpmts_meth);
    createmeta(L, METH_RPM_FI, rpmfi_meth);
    createmeta(L, METH_RPM_MI, rpmmi_meth);
    createmeta(L, METH_RPM_HEADER, rpmheader_meth);

    return 1;
}
