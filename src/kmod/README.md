# sysmon Kernel Module

This directory contains `sysmon`, an optional Linux kernel module used for
kernel-side monitoring and filter experiments.

Most of Loongshield does not depend on it. The normal userspace workflows,
including `loongshield seharden` and `loongshield rpm`, are designed to work
without loading this module.

## What It Is For

- kernel-level monitoring work that does not fit cleanly in userspace
- low-level experiments near the runtime boundary
- development work on optional host capabilities

## What It Is Not

- not required for normal Loongshield use
- not a stable public interface
- not a broad, production-ready kernel support package for every distro

## Build

From the repository root:

```sh
make kmod
```

Or from this directory:

```sh
make
```

Requirements:

- a Linux host
- kernel headers for the running kernel
- a working compiler toolchain for out-of-tree kernel modules
- root privileges to load or unload the module

The current source path is written for x86-family kernels. As the code stands,
the build guard in `filter.h` is effectively aimed at `x86_64`.

The build output is:

```text
src/kmod/sysmon.ko
```

## Load And Unload

```sh
sudo insmod src/kmod/sysmon.ko
sudo rmmod sysmon
```

For a clean rebuild:

```sh
make -C src/kmod clean
make kmod
```

## Quick Checks

After loading the module, useful checks are:

```sh
dmesg | tail
ls /sys/kernel/security/sysmon
cat /sys/kernel/security/sysmon/version
```

If you already built the userspace runtime, the helper script in
`tests/manual/kmod.lua` can be used for simple inspection:

```sh
build/src/daemon/loonjit tests/manual/kmod.lua lsmod
build/src/daemon/loonjit tests/manual/kmod.lua modprobe
```

## Notes

Kernel code is higher risk than the rest of this repository. Treat this module
as an optional advanced component, and test it on a compatible Linux system
before trying it on anything important.
