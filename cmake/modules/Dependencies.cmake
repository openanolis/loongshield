# Dependencies.cmake - Centralized dependency paths
#
# Provides variables for all dependency include directories to eliminate
# duplicated relative paths like "../luajit/luajit/src" scattered across files.

# Root dependencies directory
set(LOONGSHIELD_DEPS_DIR "${CMAKE_SOURCE_DIR}/deps" CACHE PATH "Dependencies root directory")

# LuaJIT paths (used by 14+ files)
set(LUAJIT_SRC_DIR "${LOONGSHIELD_DEPS_DIR}/luajit/luajit/src")
set(LUAJIT_INCLUDE_DIR "${LUAJIT_SRC_DIR}" CACHE PATH "LuaJIT include directory")

# Lua 5.3 compatibility layer
set(LUA_COMPAT_DIR "${LOONGSHIELD_DEPS_DIR}/lua-compat-5.3/lua-compat-5.3/c-api" CACHE PATH "Lua compat include directory")

# OpenSSL (built from source)
set(OPENSSL_BUILD_DIR "${LOONGSHIELD_DEPS_DIR}/openssl/openssl")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_BUILD_DIR}/include" CACHE PATH "OpenSSL include directory")
set(OPENSSL_LIBSSL "${OPENSSL_BUILD_DIR}/libssl.a" CACHE FILEPATH "OpenSSL libssl.a")
set(OPENSSL_LIBCRYPTO "${OPENSSL_BUILD_DIR}/libcrypto.a" CACHE FILEPATH "OpenSSL libcrypto.a")

# kmod
set(KMOD_INCLUDE_DIR "${LOONGSHIELD_DEPS_DIR}/kmod/kmod" CACHE PATH "kmod include directory")

# libuv
set(LIBUV_INCLUDE_DIR "${LOONGSHIELD_DEPS_DIR}/libuv/libuv/include" CACHE PATH "libuv include directory")

# curl
set(CURL_SRC_DIR "${LOONGSHIELD_DEPS_DIR}/curl/curl")
set(CURL_INCLUDE_DIR "${CURL_SRC_DIR}/include" CACHE PATH "curl include directory")

# lyaml
set(LYAML_INCLUDE_DIR "${LOONGSHIELD_DEPS_DIR}/lyaml/lyaml/ext/include" CACHE PATH "lyaml include directory")

# libcap (built from source for newer APIs)
set(LIBCAP_INCLUDE_DIR "${LOONGSHIELD_DEPS_DIR}/libcap/libcap/libcap/include" CACHE PATH "libcap include directory")

# Log dependency paths for debugging
message(STATUS "LuaJIT include: ${LUAJIT_INCLUDE_DIR}")
message(STATUS "Lua compat include: ${LUA_COMPAT_DIR}")
