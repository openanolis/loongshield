# luajit

set(SRCS_MINILUA
    luajit/src/host/minilua.c
    )

set(SRCS_BUILDVM
    luajit/src/host/buildvm.c
    luajit/src/host/buildvm_asm.c
    luajit/src/host/buildvm_fold.c
    luajit/src/host/buildvm_lib.c
    luajit/src/host/buildvm_peobj.c
    )

set(SRCS_LUAJIT_LIB
    luajit/src/lib_base.c
    luajit/src/lib_bit.c
    luajit/src/lib_buffer.c
    luajit/src/lib_debug.c
    luajit/src/lib_ffi.c
    luajit/src/lib_io.c
    luajit/src/lib_jit.c
    luajit/src/lib_math.c
    luajit/src/lib_os.c
    luajit/src/lib_package.c
    luajit/src/lib_string.c
    luajit/src/lib_table.c
    )

set(SRCS_LIBLUAJIT ${SRCS_LUAJIT_LIB}
    luajit/src/lib_aux.c
    luajit/src/lib_init.c
    luajit/src/lj_alloc.c
    luajit/src/lj_api.c
    luajit/src/lj_asm.c
    luajit/src/lj_assert.c
    luajit/src/lj_bc.c
    luajit/src/lj_bcread.c
    luajit/src/lj_bcwrite.c
    luajit/src/lj_buf.c
    luajit/src/lj_carith.c
    luajit/src/lj_ccall.c
    luajit/src/lj_ccallback.c
    luajit/src/lj_cconv.c
    luajit/src/lj_cdata.c
    luajit/src/lj_char.c
    luajit/src/lj_clib.c
    luajit/src/lj_cparse.c
    luajit/src/lj_crecord.c
    luajit/src/lj_ctype.c
    luajit/src/lj_debug.c
    luajit/src/lj_dispatch.c
    luajit/src/lj_err.c
    luajit/src/lj_ffrecord.c
    luajit/src/lj_func.c
    luajit/src/lj_gc.c
    luajit/src/lj_gdbjit.c
    luajit/src/lj_ir.c
    luajit/src/lj_lex.c
    luajit/src/lj_lib.c
    luajit/src/lj_load.c
    luajit/src/lj_mcode.c
    luajit/src/lj_meta.c
    luajit/src/lj_obj.c
    luajit/src/lj_opt_dce.c
    luajit/src/lj_opt_fold.c
    luajit/src/lj_opt_loop.c
    luajit/src/lj_opt_mem.c
    luajit/src/lj_opt_narrow.c
    luajit/src/lj_opt_sink.c
    luajit/src/lj_opt_split.c
    luajit/src/lj_parse.c
    luajit/src/lj_prng.c
    luajit/src/lj_profile.c
    luajit/src/lj_record.c
    luajit/src/lj_serialize.c
    luajit/src/lj_snap.c
    luajit/src/lj_state.c
    luajit/src/lj_str.c
    luajit/src/lj_strfmt.c
    luajit/src/lj_strfmt_num.c
    luajit/src/lj_strscan.c
    luajit/src/lj_tab.c
    luajit/src/lj_trace.c
    luajit/src/lj_udata.c
    luajit/src/lj_vmevent.c
    luajit/src/lj_vmmath.c
    )

source_group("minilua" FILES ${SRCS_MINILUA})
source_group("buildvm" FILES ${SRCS_BUILDVM})
source_group("luajit" FILES ${SRCS_LIBLUAJIT})


if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
    set(DASM_ARCH x64)
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86")
    set(DASM_ARCH x86)
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
    set(DASM_ARCH arm64)
elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
    set(DASM_ARCH arm)
else ()
endif ()

################################# minilua #################################

add_executable(minilua ${SRCS_MINILUA})

# LINUX variable is defined in cmake 3.25
if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    target_link_libraries(minilua m)    # math library
endif ()

################################# buildvm #################################

set(INC_LUAJIT_H src/luajit.h)
set(DASM_TARGET src/host/buildvm_arch.h)
set(DASM_FLAGS -D ENDIAN_LE -D JIT -D FFI -D FPU -D HFABI -D VER=)

# 32-bit or 64-bit
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    list(APPEND DASM_FLAGS -D P64)
endif ()

# Windows
if (WIN32)
    list(APPEND DASM_FLAGS -D WIN)
endif ()

add_custom_command(OUTPUT ${INC_LUAJIT_H}
    # Use a static timestamp instead of a git command to ensure build reproducibility.
    COMMAND ${CMAKE_COMMAND} -E echo "1672531200" > luajit_relver.txt
    COMMAND $<TARGET_FILE:minilua> host/genversion.lua
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/luajit/src"
    DEPENDS minilua
    )
add_custom_command(OUTPUT ${DASM_TARGET}
    COMMAND $<TARGET_FILE:minilua> dynasm/dynasm.lua ${DASM_FLAGS} -o ${DASM_TARGET} src/vm_${DASM_ARCH}.dasc
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/luajit"
    DEPENDS minilua
    )

add_executable(buildvm ${SRCS_BUILDVM} ${INC_LUAJIT_H} ${DASM_TARGET})
target_include_directories(buildvm
    PRIVATE "luajit/src"
    PRIVATE "luajit/dynasm"
    )

# for minilua and buildvm
set_target_properties(minilua buildvm
    PROPERTIES
    COMPILE_FLAGS "-DLUAJIT_TARGET=LUAJIT_ARCH_${DASM_ARCH} -DLJ_ARCH_HASFPU=1 -DLJ_ABI_SOFTFP=0 -DLUAJIT_ENABLE_LUA52COMPAT"
    )

################################# libluajit #################################

if (APPLE)
    #set(CMAKE_EXE_LINKER_FLAGS "-pagezero_size 10000 -image_base 100000000")
    #set(CMAKE_SHARED_LINKER_FLAGS "-image_base 7fff04c4a000")
    set(LJVM_MODE machasm)
else ()
    set(LJVM_MODE elfasm)
endif ()

macro (buildvm_target target mode)
    if (IS_ABSOLUTE "${target}")
        set(out_target "${target}")
    else ()
        set(out_target "${CMAKE_CURRENT_SOURCE_DIR}/${target}")
    endif ()
    set(temp_target "${out_target}.tmp")
    add_custom_command(OUTPUT ${temp_target}
        COMMAND $<TARGET_FILE:buildvm> -m ${mode} -o ${temp_target} ${ARGN}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        DEPENDS buildvm
        )
    # Compare the temporary file with the target file, if different, update the target file
    add_custom_command(OUTPUT ${out_target}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${temp_target} ${out_target}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        DEPENDS ${temp_target}
        )
    if (NOT IS_ABSOLUTE "${target}")
        set_source_files_properties(${target} PROPERTIES GENERATED TRUE)
    endif ()
endmacro ()

# XXX: PRE_BUILD only support MSVC

if (WIN32)
    buildvm_target(${CMAKE_CURRENT_BINARY_DIR}/lj_vm.obj peobj)
    set(LJVM_SRC ${CMAKE_CURRENT_BINARY_DIR}/lj_vm.obj)
else ()
    buildvm_target(${CMAKE_CURRENT_BINARY_DIR}/lj_vm.S ${LJVM_MODE})
    set(LJVM_SRC ${CMAKE_CURRENT_BINARY_DIR}/lj_vm.S)
    set_property(SOURCE ${CMAKE_CURRENT_BINARY_DIR}/lj_vm.S PROPERTY LANGUAGE C)
endif ()

buildvm_target(luajit/src/lj_ffdef.h   ffdef   ${SRCS_LUAJIT_LIB})
buildvm_target(luajit/src/lj_bcdef.h   bcdef   ${SRCS_LUAJIT_LIB})
buildvm_target(luajit/src/lj_recdef.h  recdef  ${SRCS_LUAJIT_LIB})
buildvm_target(luajit/src/lj_libdef.h  libdef  ${SRCS_LUAJIT_LIB})
buildvm_target(luajit/src/lj_vmdef.h   vmdef   ${SRCS_LUAJIT_LIB})
buildvm_target(luajit/src/lj_folddef.h folddef luajit/src/lj_opt_fold.c)

set(DEP_SRCS
    ${LJVM_SRC}
    luajit/src/lj_bcdef.h
    luajit/src/lj_ffdef.h
    luajit/src/lj_libdef.h
    luajit/src/lj_recdef.h
    luajit/src/lj_vmdef.h
    luajit/src/lj_folddef.h
    )

source_group("deps" FILES ${DEP_SRCS})

add_library(libluajit STATIC ${SRCS_LIBLUAJIT} ${DEP_SRCS})
target_include_directories(libluajit
    PRIVATE "luajit/src"
    )

################################# luajit #################################

#set(SRCS_LUAJIT luajit/src/luajit.c)
#source_group("src" FILES ${SRCS_LUAJIT})
#add_executable(luajit ${SRCS_LUAJIT})
#target_link_libraries(luajit libluajit)

set_target_properties(libluajit #luajit
    PROPERTIES
    COMPILE_FLAGS "-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -U_FORTIFY_SOURCE -DLUA_MULTILIB=\"lib\" -DLUAJIT_UNWIND_EXTERNAL -DLUAJIT_ENABLE_LUA52COMPAT"
    )

set_target_properties(libluajit
    PROPERTIES
    FOLDER "deps"
    )

set_target_properties(minilua buildvm #luajit
    PROPERTIES
    FOLDER "deps/tools"
    )
