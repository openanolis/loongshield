# FindSystemd.cmake - Proper systemd detection (replaces fragile ldd+grep)
#
# Provides:
#   LOONGSHIELD_SYSTEMD_FOUND       - Whether systemd was found
#   LOONGSHIELD_SYSTEMD_LIBRARIES   - Main systemd library
#   LOONGSHIELD_SYSTEMD_SHARED      - systemd-shared library (for internal APIs)

find_package(PkgConfig QUIET)

if(PKG_CONFIG_FOUND)
    pkg_check_modules(SYSTEMD QUIET libsystemd)
endif()

if(SYSTEMD_FOUND)
    set(LOONGSHIELD_SYSTEMD_FOUND TRUE)
    set(LOONGSHIELD_SYSTEMD_LIBRARIES ${SYSTEMD_LIBRARIES})
    set(LOONGSHIELD_SYSTEMD_INCLUDE_DIRS ${SYSTEMD_INCLUDE_DIRS})
else()
    # Fallback: Manual detection
    find_library(LOONGSHIELD_SYSTEMD_LIBRARIES
        NAMES systemd
        PATHS ${LOONGSHIELD_LIB_DIR} /usr/lib64 /usr/lib /lib64 /lib
    )

    find_path(LOONGSHIELD_SYSTEMD_INCLUDE_DIRS
        NAMES systemd/sd-bus.h
        PATHS /usr/include
    )

    if(LOONGSHIELD_SYSTEMD_LIBRARIES AND LOONGSHIELD_SYSTEMD_INCLUDE_DIRS)
        set(LOONGSHIELD_SYSTEMD_FOUND TRUE)
    else()
        set(LOONGSHIELD_SYSTEMD_FOUND FALSE)
    endif()
endif()

# Find systemd-shared library (for internal APIs)
# This replaces the fragile: ldd `which systemd` | grep libsystemd-shared
if(LOONGSHIELD_SYSTEMD_FOUND)
    # Search common locations for systemd-shared
    set(SYSTEMD_SHARED_SEARCH_PATHS
        "${LOONGSHIELD_LIB_DIR}/systemd"
        /usr/lib64/systemd
        /usr/lib/systemd
        /lib64/systemd
        /lib/systemd
        /usr/lib/x86_64-linux-gnu/systemd
        /usr/lib/aarch64-linux-gnu/systemd
    )

    # Try to find versioned library via glob
    foreach(search_path ${SYSTEMD_SHARED_SEARCH_PATHS})
        file(GLOB SYSTEMD_SHARED_CANDIDATES "${search_path}/libsystemd-shared-*.so")
        if(SYSTEMD_SHARED_CANDIDATES)
            list(GET SYSTEMD_SHARED_CANDIDATES 0 LOONGSHIELD_SYSTEMD_SHARED)
            break()
        endif()
    endforeach()

    # If not found via glob, try direct name
    if(NOT LOONGSHIELD_SYSTEMD_SHARED)
        find_library(LOONGSHIELD_SYSTEMD_SHARED
            NAMES systemd-shared
            PATHS ${SYSTEMD_SHARED_SEARCH_PATHS}
            NO_DEFAULT_PATH
        )
    endif()
endif()

if(LOONGSHIELD_SYSTEMD_FOUND)
    message(STATUS "Found systemd: ${LOONGSHIELD_SYSTEMD_LIBRARIES}")
    if(LOONGSHIELD_SYSTEMD_SHARED)
        message(STATUS "Found systemd-shared: ${LOONGSHIELD_SYSTEMD_SHARED}")
    else()
        message(STATUS "systemd-shared not found (some features may not work)")
    endif()
else()
    message(WARNING "systemd not found - some features will be disabled")
endif()
