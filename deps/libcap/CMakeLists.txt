include(source.cmake)

source_group("cap" FILES ${SRCS_LIBCAP})

#### 1. uapi/linux/capability.h  --->  cap_names.list.h

set(NAMESLIST libcap/libcap/cap_names.list.h)
set(CAPNAMES libcap/libcap/cap_names.h)

add_custom_command(OUTPUT ${NAMESLIST}
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/mknameslist.sh
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/libcap/libcap"
)

#### 2. cap_names.list.h (_makenames)  -->  cap_names.h

add_executable(_makenames
    libcap/libcap/_makenames.c
    ${NAMESLIST}
)

add_custom_command(OUTPUT ${CAPNAMES}
    COMMAND $<TARGET_FILE:_makenames> > cap_names.h
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/libcap/libcap"
    DEPENDS _makenames
)

### 3. static lib (cap)

add_library(cap STATIC ${SRCS_LIBCAP} ${CAPNAMES})

target_include_directories(cap
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/libcap/libcap/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/libcap/libcap"
)

set_target_properties(cap PROPERTIES FOLDER "cap")

### 4. psx library (thread-safe syscalls for capabilities)

add_library(psx STATIC
    libcap/psx/psx.c
    libcap/psx/psx_calls.c
)

target_include_directories(psx
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/libcap/psx"
)

target_link_libraries(psx PRIVATE pthread)

set_target_properties(psx PROPERTIES FOLDER "cap")
