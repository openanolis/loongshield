cmake_minimum_required(VERSION 3.16)

project(loongshield C)

# Add cmake modules path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

# Load our modules
include(Platform)
include(Dependencies)
include(CompilerFlags)
include(FindDBus)
include(FindSystemd)
include(LuaBinding)

set(CMAKE_USE_RELATIVE_PATHS ON)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

add_subdirectory(deps)
add_subdirectory(src)

add_custom_target(run_tests
    COMMAND $<TARGET_FILE:loonjit> ${CMAKE_SOURCE_DIR}/run_tests.lua
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS loonjit
    COMMENT "Running Lua unit tests..."
)
