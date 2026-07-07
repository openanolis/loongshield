# Agents Guidelines for Loongshield

Loongshield is host security tooling for RPM-based Linux systems. It combines profile-driven auditing, optional hardening actions, RPM package file verification, and Lua-LSM management in a native C/Lua runtime.

These guidelines are for AI coding agents and reviewers. Use them together with `.github/copilot-instructions.md` and the path-specific files under `.github/instructions/`.

## Repository Layout

| Path | Purpose |
|---|---|
| `src/daemon/` | C entry point, embedded Lua runtime, Lua bindings, and first-party Lua modules |
| `src/cli/` | Thin CLI front end |
| `src/kmod/` | Optional kernel module; not required for normal userspace workflows |
| `profiles/seharden/` | Bundled hardening profiles; profile semantics are user-facing behavior |
| `profiles/lua-lsm/` | Bundled Lua-LSM policy examples and manifest |
| `tests/` | Lua test runner, unit tests, integration tests, and process-level CLI tests |
| `docs/reference/` | Public CLI and profile-format contracts |
| `docs/design/` | Maintainer-facing design notes |
| `dist/` | RPM packaging and release metadata |

## Development Environment

Supported local development hosts are RPM-based Linux systems:

- Alibaba Cloud Linux 4
- Anolis OS 23
- EL9-compatible hosts such as CentOS Stream 9

Use the Docker workflow in `docs/developer/docker-development.md` when the local host is not suitable for a native build.

## Build And Test

Common commands:

```sh
make bootstrap       # install build requirements and build
make build           # configure and build
make test-quick      # unit + integration tests against the current build
make test-e2e        # process-level CLI tests
make test            # full local test suite
make fmt-check       # check formatting for changed first-party files
make fmt             # format changed first-party Lua, C, header, and YAML files
make rpm             # build RPMs locally
make rpm-in-docker   # build RPMs in the project container
```

`make test` builds first and runs the full Lua suite. `make test-quick` reuses the current build and is appropriate after narrow Lua module changes. `make test-e2e` is the right check for process-level CLI behavior.

## Coding And Review Guidelines

- Keep changes small and focused. Do not mix feature work, refactors, formatting, and unrelated cleanup.
- Match existing module boundaries before adding new abstractions.
- Treat documented CLI behavior, machine-readable output, SEHarden profile format, RPM metadata, and release workflow as compatibility contracts.
- Update implementation, tests, and docs together when user-visible behavior changes.
- Prefer explicit, testable helpers over broad framework-like rewrites.
- Do not assume root privileges, systemd availability, Lua-LSM kernel support, or a specific RPM distribution unless the code checks it or documentation says so.

## Security-Sensitive Areas

- C/Lua bindings: check Lua stack balance, userdata lifetime, ownership, cleanup ordering, NULL checks, and integer conversions.
- SEHarden enforcers: keep actions narrow, idempotent, strictly validated, and dependency-injectable for tests.
- Host writes: avoid unsafe shell construction, symlink-following writes, broad recursive filesystem changes, non-atomic config writes, and non-convergent hardening actions.
- Lua-LSM: never silently load arbitrary policies; check kernel/securityfs support before relying on it.
- Packaging and CI: keep workflow permissions minimal and avoid exposing secrets.

## Commit And PR Expectations

Commit titles must use:

```text
type(scope): short subject
```

Every commit must include a signoff trailer (`git commit -s`).

PR descriptions should include what changed, why, user-visible/security/packaging impact, and the exact validation commands that were actually run.
