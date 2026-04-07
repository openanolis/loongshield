# CompilerFlags.cmake - Common compiler settings and feature detection

include(CheckCCompilerFlag)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

# Common warning flags
set(LOONGSHIELD_COMMON_WARNINGS
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-sign-compare
)

# Debug vs Release flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(LOONGSHIELD_DEBUG ON CACHE BOOL "Debug build")
    set(LOONGSHIELD_OPT_FLAGS -g -O0)
else()
    set(LOONGSHIELD_DEBUG OFF CACHE BOOL "Debug build")
    set(LOONGSHIELD_OPT_FLAGS -O2)
endif()

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Function to apply standard compile options to a target
function(loongshield_target_compile_options TARGET_NAME)
    target_compile_options(${TARGET_NAME} PRIVATE
        ${LOONGSHIELD_COMMON_WARNINGS}
        ${LOONGSHIELD_OPT_FLAGS}
    )
endfunction()
