# Runtime Architecture

This section documents how Loongshield is built and how its major runtime components fit together. Public CLI behavior is documented in `docs/reference/`.

For a step-by-step walkthrough from build-time packaging to runtime dispatch, see [boot-and-runtime-flow.md](./boot-and-runtime-flow.md).

## Major Components

- `loongshield`: main daemon binary, entry point at `src/daemon/main.c`
- `loonjit`: bundled Lua runtime used to execute embedded modules
- `src/daemon/modules/`: embedded Lua command and feature modules
- `src/kmod/`: optional `sysmon` kernel module
- `src/lib/`: shared C helpers

## Command Layer

The top-level command dispatcher lives in `src/daemon/modules/init.lua` and routes caller input to:

- `seharden`: profile-driven audit and reinforce workflows
- `rpm`: remote SBOM-backed RPM verification

For outside users, the CLI is the stable contract. Internal Lua module names should not be treated as a supported external API.

## Build Flow

The daemon uses a staged build:

1. Build `loonjit` and the native Lua bindings.
2. Run `src/daemon/build.lua` to package Lua modules into generated headers.
3. Build `loongshield` with the embedded ramfs payload.

The top-level `Makefile` wraps CMake and writes outputs under `build/`.

## SEHarden Execution Model

- `profile.lua` resolves a named profile or explicit YAML path.
- `engine.lua` executes probes, evaluates assertions, and optionally runs enforcers.
- Probe output is exposed to later assertions through `%{probe.<name>}` interpolation.
- Reinforce mode re-runs the audit after actions to confirm the fix.

## Documentation Boundary

- Caller usage, examples, exit codes: `docs/reference/`
- Runtime and module layout: `docs/design/`
- Local build and packaging workflow: `docs/developer/`
