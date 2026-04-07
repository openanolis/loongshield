# FindDBus.cmake - Cross-platform DBus detection with architecture support
#
# Provides:
#   LOONGSHIELD_DBUS_FOUND        - Whether DBus was found
#   LOONGSHIELD_DBUS_INCLUDE_DIRS - Include directories for DBus
#   LOONGSHIELD_DBUS_LIBRARIES    - Libraries to link
#   DBus::DBus                    - Imported target (modern CMake)

find_package(PkgConfig QUIET)

if(PKG_CONFIG_FOUND)
    pkg_check_modules(DBUS QUIET dbus-1)
endif()

if(DBUS_FOUND)
    set(LOONGSHIELD_DBUS_FOUND TRUE)
    set(LOONGSHIELD_DBUS_LIBRARIES ${DBUS_LIBRARIES})
    set(LOONGSHIELD_DBUS_INCLUDE_DIRS ${DBUS_INCLUDE_DIRS})
else()
    # Fallback: Manual detection
    find_library(LOONGSHIELD_DBUS_LIBRARIES
        NAMES dbus-1
        PATHS ${LOONGSHIELD_LIB_DIR} /usr/lib64 /usr/lib
    )

    # Main include directory
    find_path(DBUS_MAIN_INCLUDE
        NAMES dbus/dbus.h
        PATHS /usr/include/dbus-1.0
    )

    # Architecture-specific include (was hardcoded before)
    find_path(DBUS_ARCH_INCLUDE
        NAMES dbus/dbus-arch-deps.h
        PATHS
            "${LOONGSHIELD_LIB_DIR}/dbus-1.0/include"
            /usr/lib64/dbus-1.0/include
            /usr/lib/x86_64-linux-gnu/dbus-1.0/include
            /usr/lib/aarch64-linux-gnu/dbus-1.0/include
            /usr/lib/loongarch64-linux-gnu/dbus-1.0/include
    )

    if(LOONGSHIELD_DBUS_LIBRARIES AND DBUS_MAIN_INCLUDE AND DBUS_ARCH_INCLUDE)
        set(LOONGSHIELD_DBUS_FOUND TRUE)
        set(LOONGSHIELD_DBUS_INCLUDE_DIRS ${DBUS_MAIN_INCLUDE} ${DBUS_ARCH_INCLUDE})
    else()
        set(LOONGSHIELD_DBUS_FOUND FALSE)
    endif()
endif()

if(LOONGSHIELD_DBUS_FOUND)
    message(STATUS "Found DBus: ${LOONGSHIELD_DBUS_LIBRARIES}")
    message(STATUS "DBus includes: ${LOONGSHIELD_DBUS_INCLUDE_DIRS}")

    # Create imported target (modern CMake approach)
    if(NOT TARGET DBus::DBus)
        add_library(DBus::DBus INTERFACE IMPORTED)
        set_target_properties(DBus::DBus PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${LOONGSHIELD_DBUS_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${LOONGSHIELD_DBUS_LIBRARIES}"
        )
    endif()
else()
    message(FATAL_ERROR "DBus not found - required for build")
endif()
