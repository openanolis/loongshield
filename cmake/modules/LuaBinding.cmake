# LuaBinding.cmake - Helper function for building Lua binding libraries
#
# Usage:
#   loongshield_add_lua_library(
#       NAME lpeg
#       SOURCES src/lpeg.c src/lpcap.c
#       INCLUDE_DIRS extra/include
#       COMPILE_DEFINITIONS NDEBUG
#       COMPILE_OPTIONS -Wno-deprecated
#       DEPENDENCIES libopenssl
#       LINK_LIBRARIES somelib
#   )

include(CMakeParseArguments)

function(loongshield_add_lua_library)
    cmake_parse_arguments(
        LUA_LIB
        ""                                    # Options (booleans)
        "NAME;FOLDER"                         # Single-value args
        "SOURCES;INCLUDE_DIRS;COMPILE_DEFINITIONS;COMPILE_OPTIONS;DEPENDENCIES;LINK_LIBRARIES"
        ${ARGN}
    )

    if(NOT LUA_LIB_NAME)
        message(FATAL_ERROR "loongshield_add_lua_library: NAME is required")
    endif()
    if(NOT LUA_LIB_SOURCES)
        message(FATAL_ERROR "loongshield_add_lua_library: SOURCES is required")
    endif()

    # Create the static library
    add_library(${LUA_LIB_NAME} STATIC ${LUA_LIB_SOURCES})

    # Add LuaJIT and Lua compat includes (from Dependencies.cmake)
    target_include_directories(${LUA_LIB_NAME} PRIVATE
        ${LUAJIT_INCLUDE_DIR}
        ${LUA_COMPAT_DIR}
    )

    # Add extra include directories
    if(LUA_LIB_INCLUDE_DIRS)
        target_include_directories(${LUA_LIB_NAME} PRIVATE ${LUA_LIB_INCLUDE_DIRS})
    endif()

    # Add compile definitions
    if(LUA_LIB_COMPILE_DEFINITIONS)
        target_compile_definitions(${LUA_LIB_NAME} PRIVATE ${LUA_LIB_COMPILE_DEFINITIONS})
    endif()

    # Add compile options
    if(LUA_LIB_COMPILE_OPTIONS)
        target_compile_options(${LUA_LIB_NAME} PRIVATE ${LUA_LIB_COMPILE_OPTIONS})
    endif()

    # Add dependencies
    if(LUA_LIB_DEPENDENCIES)
        add_dependencies(${LUA_LIB_NAME} ${LUA_LIB_DEPENDENCIES})
    endif()

    # Link libraries
    if(LUA_LIB_LINK_LIBRARIES)
        target_link_libraries(${LUA_LIB_NAME} PRIVATE ${LUA_LIB_LINK_LIBRARIES})
    endif()

    # Set folder for IDE organization
    if(LUA_LIB_FOLDER)
        set_target_properties(${LUA_LIB_NAME} PROPERTIES FOLDER "${LUA_LIB_FOLDER}")
    else()
        set_target_properties(${LUA_LIB_NAME} PROPERTIES FOLDER "deps")
    endif()

    # Create source group for IDE
    source_group("${LUA_LIB_NAME}" FILES ${LUA_LIB_SOURCES})
endfunction()
