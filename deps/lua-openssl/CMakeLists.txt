set(SRCS_LUA_OPENSSL
    lua-auxiliar/auxiliar.c
    lua-auxiliar/subsidiar.c
    lua-openssl/src/asn1.c
    lua-openssl/src/bio.c
    lua-openssl/src/callback.c
    lua-openssl/src/cipher.c
    lua-openssl/src/cms.c
    lua-openssl/src/compat.c
    lua-openssl/src/crl.c
    lua-openssl/src/csr.c
    lua-openssl/src/dh.c
    lua-openssl/src/digest.c
    lua-openssl/src/dsa.c
    lua-openssl/src/ec.c
    lua-openssl/src/engine.c
    lua-openssl/src/hmac.c
    lua-openssl/src/lbn.c
    lua-openssl/src/lhash.c
    lua-openssl/src/mac.c
    lua-openssl/src/misc.c
    lua-openssl/src/ocsp.c
    lua-openssl/src/openssl.c
    lua-openssl/src/ots.c
    lua-openssl/src/pkcs12.c
    lua-openssl/src/pkcs7.c
    lua-openssl/src/pkey.c
    lua-openssl/src/rsa.c
    lua-openssl/src/sk.h
    lua-openssl/src/srp.c
    lua-openssl/src/ssl.c
    lua-openssl/src/th-lock.c
    lua-openssl/src/util.c
    lua-openssl/src/x509.c
    lua-openssl/src/xalgor.c
    lua-openssl/src/xattrs.c
    lua-openssl/src/xexts.c
    lua-openssl/src/xname.c
    lua-openssl/src/xstore.c
)

source_group("lua-openssl" FILES ${SRCS_LUA_OPENSSL})

# On macOS, search Homebrew for keg-only versions of OpenSSL
if(CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")
    execute_process(
        COMMAND brew --prefix OpenSSL
        RESULT_VARIABLE BREW_OPENSSL
        OUTPUT_VARIABLE BREW_OPENSSL_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(BREW_OPENSSL EQUAL 0 AND EXISTS "${BREW_OPENSSL_PREFIX}")
        message(STATUS "Found OpenSSL keg installed by Homebrew at ${BREW_OPENSSL_PREFIX}")
        set(OPENSSL_ROOT_DIR "${BREW_OPENSSL_PREFIX}/")
        set(OPENSSL_INCLUDE_DIR "${BREW_OPENSSL_PREFIX}/include")
    endif()
endif()

add_library(lua-openssl STATIC ${SRCS_LUA_OPENSSL})
add_dependencies(lua-openssl libopenssl)

target_include_directories(lua-openssl PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/lua-auxiliar"
    ${LUA_COMPAT_DIR}
    ${LUAJIT_INCLUDE_DIR}
)

target_compile_options(lua-openssl PRIVATE
    -Wno-deprecated-declarations
    -Wno-incompatible-pointer-types
)

# Target-based definition (replaces global add_definitions)
if(WIN32)
    target_compile_definitions(lua-openssl PRIVATE WIN32_LEAN_AND_MEAN)
endif()

set_target_properties(lua-openssl PROPERTIES FOLDER "deps")
