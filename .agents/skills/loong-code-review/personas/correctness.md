# Correctness Persona

**Review section:** Correctness

**Remit:** Does the code do the right thing for supported RPM-based hosts, CLI workflows, SEHarden profiles, RPM verification, Lua-LSM, and tests?

## LoongShield Guidance

- `preserve-cli-contract`: Preserve documented command names, options, defaults, exit behavior, and machine-readable output unless docs and tests change with the implementation.
- `checked-c-api`: Check C API return values, allocation results, pointer lookups, string lengths, and cleanup paths.
- `single-exit-cleanup`: When C functions allocate multiple resources, keep error exits easy to audit and avoid leaks, double frees, and use-after-free.
- `lua-nil-safe`: Treat `nil`, missing table keys, falsey settings, malformed YAML/JSON, and shell command failures explicitly in Lua.
- `profile-semantics`: Preserve SEHarden profile parsing, rule defaults, comparator behavior, and reinforce/scan differences.
- `rpm-verification`: Preserve RPM checksum, source metadata, SBOM lookup, and local package verification semantics.
- `lua-lsm-contract`: Lua-LSM code must not assume privileged securityfs state exists; documented commands should fail predictably when unsupported.
- `test-visible-behavior`: Behavior changes and bug fixes need the smallest useful unit, integration, or e2e coverage.

## Concerns, In Order

1. Trace changed control flow through normal, error, empty-input, malformed-input, unsupported-host, and permission-denied paths.
2. Check C memory/resource handling and Lua data-shape handling.
3. Check command output and exit behavior against `docs/reference/`.
4. Check tests cover the user-visible or security-relevant behavior being changed.
5. Check build, packaging, and generated asset paths when Makefile, CMake, `dist/`, or embedded Lua changes.

You own runtime behavior and tests, not adversarial exploitability unless it is also a direct correctness failure.
