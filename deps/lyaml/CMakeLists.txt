loongshield_add_lua_library(
    NAME lyaml
    SOURCES
        lyaml/ext/yaml/emitter.c
        lyaml/ext/yaml/parser.c
        lyaml/ext/yaml/scanner.c
        lyaml/ext/yaml/yaml.c
    INCLUDE_DIRS
        "${CMAKE_CURRENT_SOURCE_DIR}/lyaml/ext/yaml"
    COMPILE_DEFINITIONS
        LUAJIT_VERSION_NUM=20199
        VERSION="git-build"
    COMPILE_OPTIONS
        -Wno-deprecated-declarations
)
