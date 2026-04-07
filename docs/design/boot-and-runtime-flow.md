# Boot And Runtime Flow

This document explains how Loongshield moves from source files to a running command, and how `loonjit`, the embedded ramfs payload, and the Lua module tree fit together.

It complements [runtime-architecture.md](./runtime-architecture.md). That page describes the major components; this page walks the execution path in order.

## Overview

Loongshield has two related but different executables:

- `loonjit`: a bundled and customized LuaJIT runtime
- `loongshield`: the main daemon/CLI binary that embeds a Lua module payload

The important distinction is:

- `loonjit` runs Lua code directly from the source tree or from standard input
- `loongshield` runs Lua code that was packaged into the binary at build time

At a high level, the flow is:

```text
source Lua modules
  -> loonjit runs build.lua
  -> build.lua compiles/packages Lua assets into generated headers
  -> loongshield links those headers into the binary
  -> loongshield starts
  -> ramfs runtime mounts the embedded payload into an in-memory VFS
  -> /init executes from the VFS
  -> /init dispatches to subcommands such as seharden and rpm
```

## The Role Of `loonjit`

`src/daemon/luajit.c` builds the `loonjit` executable. It is not just a stock system `luajit` wrapper. During startup it:

1. Creates a Lua state.
2. Opens the standard Lua libraries.
3. Registers project-specific native modules with `lualibs_openall()`.
4. Processes command-line options such as `-e`, `-l`, `-j`, `-O`, and script paths.
5. Executes a script, runs a command string, reads from standard input, or starts a REPL.

The extra registration step is the key customization. `lualibs_openall()` exposes built-in modules such as:

- `archive`
- `audit`
- `capability`
- `dbus`
- `fs`
- `kmod`
- `lrpm`
- `mount`
- `openssl`
- `systemd`
- `xattr`
- `yaml`

That means `loonjit` is the project's own Lua runtime, not a dependency on the host's plain `luajit`.

## Build-Time Flow

The build flow is staged on purpose.

### 1. Build `loonjit`

`src/daemon/CMakeLists.txt` first builds `loonjit` from:

- `luajit.c`
- the native Lua bindings listed in `${SRCS_LUALIBS}`

This gives the project a known-good runtime that already contains the native bindings needed by the Lua build scripts.

### 2. Run `build.lua`

The same CMake file then runs:

```text
$<TARGET_FILE:loonjit> build.lua
```

from `src/daemon/`.

`src/daemon/build.lua` does two things:

1. Calls `runtime.ramfs.mkramfs('modules/runtime/ramfs.lua', 'bin_ramfs_luac.h')`
2. Calls `runtime.ramfs.mkinitrd('bin_initrd_tar.h', dirs)`

The first step compiles the ramfs runtime itself into Lua bytecode and writes it into a generated C header.

The second step walks `src/daemon/modules/`, compiles `.lua` files to bytecode, packs them into an archive payload, and writes that payload into another generated C header.

### 3. Link The Generated Headers Into `loongshield`

`loongshield` is then built from:

- `main.c`
- `ramfs.c`
- the native Lua bindings
- `bin_ramfs_luac.h`
- `bin_initrd_tar.h`

At that point, the daemon binary already contains:

- the LuaJIT-powered host runtime
- the VFS bootstrap logic
- the packaged Lua module tree

No external Lua source tree is required at runtime for the main command path.

## Why Ramfs Exists

Ramfs is used to make the daemon self-contained and predictable.

The packaged module tree is loaded from memory, not discovered from the host filesystem at execution time. This gives the project:

- a fixed module set that matches the binary that was built
- fewer deployment assumptions about Lua search paths on the target machine
- one main entry point for running embedded command modules

This is different from the build-time path, where `loonjit` executes `build.lua` directly from the checked-out source tree.

## Runtime Flow Inside `loongshield`

The runtime path starts in `src/daemon/main.c`.

### 1. Initialize Lua

`main.c`:

1. creates a Lua state
2. opens the standard Lua libraries
3. registers the same project-specific native modules with `lualibs_openall()`

This means the embedded Lua code sees the same native capability surface that `loonjit` sees.

### 2. Start The Embedded VFS

`main.c` then calls:

```text
ramfs_vfsinit(L, "/init", argc, argv, envp)
```

in `src/daemon/ramfs.c`.

`ramfs_vfsinit()` loads two generated blobs:

- `bin_ramfs_luac.h`: bytecode for `modules/runtime/ramfs.lua`
- `bin_initrd_tar.h`: the packaged module payload

It executes the bytecode from `bin_ramfs_luac.h`, obtains the returned `ramfs` module table, and calls:

```text
ramfs.init(initrd, "/init", argv, envp)
```

### 3. Build An In-Memory VFS

Inside `src/daemon/modules/runtime/ramfs.lua`, `init()`:

1. unpacks the embedded archive into a Lua table that represents a virtual filesystem
2. installs a custom `require()` that first resolves modules from that VFS
3. loads and executes the requested entry script from the VFS

If the requested module name is `foo.bar`, the custom resolver looks for:

- `foo/bar`
- `foo/bar/init`

inside the virtual filesystem before falling back to the normal Lua `require()`.

### 4. Execute `/init`

The entry path passed from C is `/init`, which maps to the packaged form of `src/daemon/modules/init.lua`.

That file is the top-level command dispatcher. It:

1. receives `argv` and `envp`
2. determines the requested subcommand
3. loads command modules such as `seharden` and `rpm`
4. calls each module's `run()` function

So the daemon does not manually call each feature from C. C only boots Lua and hands control to the embedded `/init` script.

## Runtime Flow Diagram

```text
loongshield
  -> main.c creates Lua state
  -> main.c opens standard libs and project native libs
  -> main.c calls ramfs_vfsinit(L, "/init", argc, argv, envp)
  -> ramfs.c loads embedded ramfs bytecode from bin_ramfs_luac.h
  -> ramfs.c loads embedded module archive from bin_initrd_tar.h
  -> runtime.ramfs.init() untars payload into an in-memory VFS
  -> runtime.ramfs overrides require() to read from the VFS first
  -> /init executes from the VFS
  -> /init dispatches to seharden or rpm
```

## What Is Customized Versus Stock LuaJIT

It is reasonable to describe Loongshield as "running on a highly customized LuaJIT-based runtime", but that description needs precision.

What is customized:

- the `loonjit` executable and startup path
- the built-in native module set
- the build pipeline that compiles and packages Lua modules into headers
- the ramfs/VFS loader used by `loongshield`
- the command dispatcher and feature modules embedded in the binary

What is not true:

- `loongshield` is not just invoking plain host `luajit` against files on disk
- ramfs is not a general replacement for all Lua execution paths
- the daemon does not scan the source tree at runtime to discover modules

The correct model is:

- build time: `loonjit` executes checked-out Lua sources
- runtime: `loongshield` executes the embedded, packaged Lua payload

## Relevant Source Files

- `src/daemon/luajit.c`
- `src/daemon/lualibs.c`
- `src/daemon/build.lua`
- `src/daemon/ramfs.c`
- `src/daemon/main.c`
- `src/daemon/modules/runtime/ramfs.lua`
- `src/daemon/modules/init.lua`
