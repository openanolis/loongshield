include(source.cmake)

find_package(PkgConfig)
pkg_check_modules(LIBPSL REQUIRED libpsl)

source_group("curl" FILES ${SRCS_CURL})

add_library(curl STATIC ${SRCS_CURL})
add_dependencies(curl libopenssl)

target_include_directories(curl PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    ${OPENSSL_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/curl/lib"
    "${CMAKE_CURRENT_SOURCE_DIR}/curl/include"
)

# Target-based definitions (replaces global add_definitions)
target_compile_definitions(curl PRIVATE BUILDING_LIBCURL)

target_compile_options(curl PRIVATE -include curl_config.h)

target_link_libraries(curl PRIVATE
    ${OPENSSL_LIBSSL}
    ${OPENSSL_LIBCRYPTO}
    psl
)

set_target_properties(curl PROPERTIES FOLDER "deps")
