set(SRCS_LUACOMPAT "lua-compat-5.3/c-api/compat-5.3.c")
add_library(lua-compat-5.3 STATIC ${SRCS_LUACOMPAT})
target_include_directories(lua-compat-5.3 PUBLIC
    "lua-compat-5.3/c-api"
    "../luajit/luajit/src"
)
set_target_properties(lua-compat-5.3 PROPERTIES FOLDER "deps/libs")
