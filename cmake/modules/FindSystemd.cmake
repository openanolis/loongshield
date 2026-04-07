# FindSystemd.cmake - Locate the public libsystemd development interface
#
# Provides:
#   LOONGSHIELD_SYSTEMD_FOUND       - Whether systemd was found
#   LOONGSHIELD_SYSTEMD_LIBRARIES   - Main systemd library
#   LOONGSHIELD_SYSTEMD_INCLUDE_DIRS - Include directories for systemd headers

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

if(LOONGSHIELD_SYSTEMD_FOUND)
    message(STATUS "Found systemd: ${LOONGSHIELD_SYSTEMD_LIBRARIES}")
    if(NOT TARGET Systemd::Systemd)
        add_library(Systemd::Systemd INTERFACE IMPORTED)
        set_target_properties(Systemd::Systemd PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${LOONGSHIELD_SYSTEMD_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${LOONGSHIELD_SYSTEMD_LIBRARIES}"
        )
    endif()
else()
    message(WARNING "systemd not found - some features will be disabled")
endif()
