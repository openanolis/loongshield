# Loongshield Copilot Instructions

Loongshield is host security tooling for RPM-based Linux systems. It combines profile-driven security auditing, optional hardening actions, RPM package file verification, and Lua-LSM management in a native C/Lua runtime.

## Project Map

- `src/daemon/`: C entry point, embedded Lua runtime, Lua bindings, and first-party Lua modules.
- `src/cli/`: thin CLI front end.
- `src/kmod/`: optional kernel module. Do not assume it is required for normal userspace workflows.
- `profiles/seharden/`: bundled hardening profiles. Profile semantics are user-facing behavior.
- `profiles/lua-lsm/`: bundled Lua-LSM policy examples and manifest.
- `tests/`: Lua test runner, unit tests, integration tests, and process-level CLI tests.
- `docs/reference/`: public CLI and profile-format contracts.
- `docs/design/`: maintainer-facing design notes.
- `dist/`: RPM packaging and release metadata.

## Review Priorities

Review for correctness, security, compatibility, and maintainability. Prioritize actionable findings that can cause incorrect hardening, host damage, privilege-boundary mistakes, broken packaging, or CLI/profile compatibility regressions.

Pay special attention to:

- C/Lua boundary safety: Lua stack balance, userdata lifetime, ownership, error paths, NULL checks, integer conversions, and resource cleanup.
- SEHarden reinforce behavior: enforcers must be narrow, idempotent, strictly validate inputs, return `true` on success or `nil, err` on failure, and keep dependencies injectable for tests.
- Host safety: avoid unsafe shell construction, symlink-following writes, broad recursive filesystem changes, non-atomic config writes, and changes that cannot converge when run repeatedly.
- RPM/systemd assumptions: changes should work on supported RPM-based Linux hosts, especially Alibaba Cloud Linux 4, Anolis OS 23, and EL9-compatible systems.
- User-facing contracts: documented CLI options, exit behavior, machine-readable output, SEHarden profile format, RPM metadata, and release workflow must remain compatible unless docs and tests change with the code.
- Lua-LSM behavior: managing policies through securityfs must not silently load arbitrary policies or assume kernel support without checking.

## Validation Expectations

Use the smallest useful validation for the changed area:

- General build and full test: `make test`
- Fast Lua module checks after an existing build: `make test-quick`
- Process-level CLI behavior: `make test-e2e`
- Formatting for changed first-party files: `make fmt-check`
- RPM packaging: `make rpm` or `make rpm-in-docker`

Do not claim a validation command passed unless there is evidence in the PR or CI.

## Style And Change Discipline

- Keep changes focused. Do not mix unrelated cleanup with feature or bug-fix work.
- Match existing style and module boundaries before suggesting new abstractions.
- Prefer small, explicit helpers over broad framework-like rewrites.
- Treat docs in `docs/reference/` and bundled profiles as compatibility surfaces.
- For behavior changes, expect tests and documentation updates in the same PR.

## Review Output

When reviewing, explain the failing scenario, cite the affected file and line, and propose a minimal fix. Avoid speculative comments that depend on unproven assumptions. If a concern is only a maintainability suggestion, label it as such and do not present it as a correctness bug.
