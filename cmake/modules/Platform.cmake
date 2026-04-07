# Platform.cmake - OS, distribution, and architecture detection
#
# Provides:
#   LOONGSHIELD_DISTRO_NAME  - Distribution name (ubuntu, centos, anolis, etc.)
#   LOONGSHIELD_ARCH         - Architecture (x86_64, aarch64, etc.)
#   LOONGSHIELD_ARCH_BITS    - Architecture bits (32 or 64)
#   LOONGSHIELD_LIB_DIR      - Platform-specific library directory

# Architecture detection with ARM64 support
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    set(LOONGSHIELD_ARCH "x86_64")
    set(LOONGSHIELD_ARCH_BITS 64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set(LOONGSHIELD_ARCH "aarch64")
    set(LOONGSHIELD_ARCH_BITS 64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i686|i386|x86")
    set(LOONGSHIELD_ARCH "x86")
    set(LOONGSHIELD_ARCH_BITS 32)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "loongarch64")
    set(LOONGSHIELD_ARCH "loongarch64")
    set(LOONGSHIELD_ARCH_BITS 64)
else()
    set(LOONGSHIELD_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
    set(LOONGSHIELD_ARCH_BITS 64)
endif()

# Distribution detection via /etc/os-release (most reliable method)
set(LOONGSHIELD_DISTRO_NAME "unknown")

if(EXISTS "/etc/os-release")
    file(STRINGS "/etc/os-release" OS_RELEASE_CONTENTS)
    foreach(line ${OS_RELEASE_CONTENTS})
        if(line MATCHES "^ID=[\"]?([^\"]+)[\"]?$")
            set(LOONGSHIELD_DISTRO_NAME "${CMAKE_MATCH_1}")
            break()
        endif()
    endforeach()
endif()

# Normalize distro name to lowercase
string(TOLOWER "${LOONGSHIELD_DISTRO_NAME}" LOONGSHIELD_DISTRO_NAME)

# Determine library directory based on distro and architecture
if(LOONGSHIELD_DISTRO_NAME MATCHES "ubuntu|debian")
    # Debian/Ubuntu multiarch layout
    if(LOONGSHIELD_ARCH STREQUAL "x86_64")
        set(LOONGSHIELD_LIB_ARCH "x86_64-linux-gnu")
    elseif(LOONGSHIELD_ARCH STREQUAL "aarch64")
        set(LOONGSHIELD_LIB_ARCH "aarch64-linux-gnu")
    elseif(LOONGSHIELD_ARCH STREQUAL "i386" OR LOONGSHIELD_ARCH STREQUAL "x86")
        set(LOONGSHIELD_LIB_ARCH "i386-linux-gnu")
    else()
        set(LOONGSHIELD_LIB_ARCH "${LOONGSHIELD_ARCH}-linux-gnu")
    endif()
    set(LOONGSHIELD_LIB_DIR "/usr/lib/${LOONGSHIELD_LIB_ARCH}")
else()
    # RHEL/CentOS/Anolis/Fedora style
    if(LOONGSHIELD_ARCH_BITS EQUAL 64)
        set(LOONGSHIELD_LIB_DIR "/usr/lib64")
    else()
        set(LOONGSHIELD_LIB_DIR "/usr/lib")
    endif()
endif()

# Log detected platform info
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME} ${LOONGSHIELD_ARCH}")
message(STATUS "Distribution: ${LOONGSHIELD_DISTRO_NAME}")
message(STATUS "Library directory: ${LOONGSHIELD_LIB_DIR}")
