# RPM Verification Design

This page covers the internal flow behind `loongshield rpm`. For operator usage, see `docs/reference/rpm-cli.md`.

## Module Layout

- `src/daemon/modules/rpm/cli.lua`: CLI parsing and exit behavior
- `src/daemon/modules/rpm/verify.lua`: orchestration and result summary
- `src/daemon/modules/rpm/sbom.lua`: SBOM fetch and SPDX parsing
- `src/daemon/modules/rpm/checksum.lua`: local file enumeration and SHA256 hashing
- `src/daemon/lua_rpm.c`: Lua bindings to the RPM database

## Verification Flow

1. Detect an RPM database path, preferring rpm-configured values and common distro defaults.
2. Resolve package `name`, `version`, `release`, and `arch`.
3. Expand the SBOM URL template.
4. Download and parse SPDX JSON.
5. Enumerate installed files for the package.
6. Hash local files and compare them with SBOM checksums.
7. Print a summary and return a status code.

## Current Behavior

- Config files are skipped unless `--verify-config` is set.
- Missing SBOM entries are reported separately from checksum mismatches.
- The command uses libuv-backed async fetch logic, so the CLI runs inside a coroutine and then drains the event loop.

## Current Limits

- The public API is CLI-only; there is no stable config file format yet.
- SBOM trust currently depends on transport and repository integrity; detached signature verification is not implemented.
- Packages without published SBOMs fail as fetch or lookup errors rather than soft warnings.
