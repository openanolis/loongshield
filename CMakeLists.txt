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

set(LOONGSHIELD_TEST_ENV
    LOONGSHIELD_BIN=$<TARGET_FILE:loongshield>
    LOONGSHIELD_E2E_BIN=$<TARGET_FILE:loongshield>
    LOONGSHIELD_SRC_DIR=${CMAKE_SOURCE_DIR}
)

add_custom_target(run_tests
    COMMAND ${CMAKE_COMMAND} -E env
        ${LOONGSHIELD_TEST_ENV}
        $<TARGET_FILE:loonjit> ${CMAKE_SOURCE_DIR}/tests/run.lua --type all
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS loongshield
    COMMENT "Running Lua test suite..."
)

add_custom_target(run_tests_quick
    COMMAND ${CMAKE_COMMAND} -E env
        ${LOONGSHIELD_TEST_ENV}
        $<TARGET_FILE:loonjit> ${CMAKE_SOURCE_DIR}/tests/run.lua --type unit,integration
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS loongshield
    COMMENT "Running Lua unit/integration tests..."
)

add_custom_target(run_tests_e2e
    COMMAND ${CMAKE_COMMAND} -E env
        ${LOONGSHIELD_TEST_ENV}
        $<TARGET_FILE:loonjit> ${CMAKE_SOURCE_DIR}/tests/run.lua --type e2e
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS loongshield
    COMMENT "Running Lua end-to-end tests..."
)
