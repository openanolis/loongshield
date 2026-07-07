---
applyTo: "src/**/*.c,src/**/*.h,cmake/**/*.cmake,CMakeLists.txt,deps/**"
---

# C Runtime Review Instructions

Review C changes with extra care around the embedded Lua runtime and host bindings.

- Check Lua stack discipline on every path, especially errors and early returns.
- Check userdata lifetime, pointer ownership, and cleanup ordering.
- Validate all external input before passing it to filesystem, process, rpm, systemd, DBus, xattr, curl, archive, or kernel-module helpers.
- Prefer explicit cleanup blocks over duplicated cleanup paths.
- Do not introduce silent truncation, unchecked signed/unsigned conversions, unchecked allocation results, or unchecked `snprintf`/string-building results.
- Preserve existing build behavior across supported Linux targets and architectures.
- Treat vendored dependency changes under `deps/` as high risk. Verify the source policy and avoid unnecessary changes there.
