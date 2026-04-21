# SEHarden Refactor Plan

This page tracks the current SEHarden cleanup effort.

## Context

The top-level Loongshield architecture is still sound:

- a thin runtime edge in C and native bindings
- policy, orchestration, and CLI logic in Lua and YAML

The current cleanup target is narrower. Complexity has accumulated inside
`src/daemon/modules/seharden/`, especially around:

- the execution flow in `engine.lua`
- duplicated host-integration code in probe and enforcer pairs
- benchmark-shaped modules such as `probes/pam.lua`

## Goals

- Reduce change amplification inside the SEHarden execution path.
- Move repeated host-integration logic behind shared modules.
- Split large benchmark-shaped modules into smaller policy-oriented modules.
- Keep the external CLI and profile format stable during the refactor.

## Non-Goals

- No YAML profile DSL redesign in this series.
- No operator-facing CLI behavior changes unless required for correctness.
- No broad cleanup outside SEHarden and its immediate helpers.

## Guardrails

- Keep commits small and single-purpose.
- Run `make test` before every commit.
- Preserve current behavior unless a failing test or clear bug requires a fix.
- Prefer extracting existing logic over rewriting it.

## Planned Sequence

### 1. Plan And Branch Setup

- Add this document.
- Create a dedicated refactor branch.

### 2. Extract Shared Systemd Adapter

- Introduce a shared helper for:
  - `systemctl` path discovery
  - unit name sanitization and normalization
  - command execution wrappers used by service probes and enforcers
- Repoint `seharden.probes.services` and `seharden.enforcers.services` to it.

Expected outcome:

- service probe and enforce flows stop carrying duplicated command plumbing
- later service changes touch one adapter instead of two modules

### 3. Extract Shared RPM Package Inventory Adapter

- Introduce a shared helper for installed-package enumeration and glob matching.
- Reuse it from:
  - `seharden.probes.packages`
  - `seharden.enforcers.packages`

Expected outcome:

- package inventory behavior becomes consistent across probe and reinforce code
- RPM lookup changes stop leaking into multiple modules

### 4. Extract Shared Commented Key-Value Parsing Helper

- Introduce a shared helper for:
  - stripping inline comments
  - parsing `key=value` and `key value` lines
  - loading optional config files when appropriate
- Reuse it from:
  - `seharden.probes.file`
  - `seharden.probes.pam`

Expected outcome:

- config parsing behavior becomes consistent across file-oriented probes
- PAM-specific modules lose unrelated text-processing code

### 5. Extract Shared Template Resolver

- Move `%{probe.*}` and `%{item.*}` resolution into a dedicated helper module.
- Reuse it from:
  - `seharden.engine`
  - `seharden.probes.meta`

Expected outcome:

- template semantics live in one place
- future interpolation changes do not require synchronized edits in multiple files

### 6. Split Engine Internals By Responsibility

- Keep `seharden.engine.run` as the stable entrypoint.
- Extract internal responsibilities into focused modules:
  - assertion evaluation
  - rule execution and probe dispatch
  - reinforce execution flow

Expected outcome:

- `engine.lua` becomes a shallow coordinator instead of a multi-purpose module
- tests can target evaluation and execution behavior separately

### 7. Split PAM Probe Logic By Policy Family

- Keep the public probe entrypoints stable.
- Move shared PAM file loading and option helpers into a common module.
- Separate policy-specific logic for:
  - password history
  - pwquality
  - faillock
  - wheel

Expected outcome:

- PAM changes stop accumulating in one file
- adding a new PAM-related rule no longer requires reading unrelated policy logic

## Verification

Every step in this series should satisfy all of the following before commit:

1. `make test` passes.
2. The diff stays focused on one refactor step.
3. Existing public entrypoints remain stable unless explicitly documented.

## Exit Criteria

This refactor series is complete when:

- repeated host-integration logic has a shared home
- `engine.lua` is no longer the main complexity hotspot
- `probes/pam.lua` is reduced to a small coordinator or removed in favor of
  smaller modules
- the full test suite still passes
