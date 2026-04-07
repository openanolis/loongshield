set(SRCS_LUA_CJSON
    lua-cjson/fpconv.c
    lua-cjson/lua_cjson.c
    lua-cjson/strbuf.c
)

source_group("lua-cjson" FILES ${SRCS_LUA_CJSON})

add_library(lua-cjson STATIC ${SRCS_LUA_CJSON})

target_include_directories(lua-cjson PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    ${LUAJIT_INCLUDE_DIR}
)

# Target-based definitions (replaces global add_definitions)
target_compile_definitions(lua-cjson PRIVATE NDEBUG)

# MSVC-specific definitions
if(MSVC)
    target_compile_definitions(lua-cjson PRIVATE
        _CRT_SECURE_NO_WARNINGS
        inline=__inline
        strncasecmp=_strnicmp
        MISSING_ISINF
    )
    if(MSVC_VERSION LESS_EQUAL 1500)
        target_compile_definitions(lua-cjson PRIVATE
            snprintf=_snprintf
            isnan=_isnan
        )
    endif()
endif()

set_target_properties(lua-cjson PROPERTIES FOLDER "deps")
