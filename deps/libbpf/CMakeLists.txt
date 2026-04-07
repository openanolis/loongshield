include(source.cmake)

source_group("bpf" FILES ${SRCS_LIBBPF})

add_library(bpf STATIC ${SRCS_LIBBPF})

target_include_directories(bpf PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/uapi"
)

# Target-based definition (replaces global add_definitions)
target_compile_definitions(bpf PRIVATE BUILD_STATIC_ONLY)

set_target_properties(bpf PROPERTIES FOLDER "deps")
