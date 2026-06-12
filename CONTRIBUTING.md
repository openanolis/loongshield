# Contributing to Loongshield

This guide covers the expected workflow for Loongshield contributors.
Detailed coding and review standards live in
[docs/developer/coding-standards.md](docs/developer/coding-standards.md).

## Development Environment

Loongshield is developed and tested on RPM-based Linux systems:

- Alibaba Cloud Linux 4
- Anolis OS 23
- EL9-compatible hosts such as CentOS Stream 9

For a fresh checkout on a supported host:

```sh
make bootstrap
make test
```

If the local host is not suitable for native builds, use the Docker workflow in
[docs/developer/docker-development.md](docs/developer/docker-development.md).

## Common Commands

```sh
make build          # configure and build
make test-quick     # unit + integration tests against the current build
make test-e2e       # process-level CLI tests
make test           # full local test suite
make fmt-check      # check formatting for changed first-party files
make fmt            # format changed first-party Lua, C, header, and YAML files
make rpm            # build RPMs locally
make rpm-in-docker  # build RPMs in the project container
```

For more detail, see [docs/developer/build-and-test.md](docs/developer/build-and-test.md).

## Contribution Process

1. Base new work on `main` unless a maintainer asks for another branch.
2. Keep each PR small and focused. Do not mix feature work, refactors, and unrelated cleanup.
3. Match existing code style and module boundaries before adding new abstractions.
4. Add or update tests for behavior changes and bug fixes.
5. Update docs when changing user-visible commands, machine-readable output, profile semantics,
   packaging behavior, or release workflow.
6. Run the smallest useful validation locally, then list the exact commands in the PR.

## Public Contracts

Treat these surfaces as contracts:

- Documented CLI options, exit behavior, and examples under `docs/reference/`.
- Machine-readable CLI output, especially JSON output. JSON must include a `schema_version`
  when it is consumed by another tool.
- SEHarden profile format and rule semantics under `docs/reference/seharden-profile-format.md`.
- RPM source, spec, version, and commit metadata behavior under `dist/` and `Makefile`.

Human-readable text output is for operators. Other tools should consume explicit
machine-readable formats instead of parsing default text output.

When a contract changes, update the implementation, docs, tests, and known downstream
consumers in the same change whenever possible.

## Commit Messages

Loongshield checks commit titles and signoff trailers in CI.

Use:

```text
type(scope): short subject
```

Examples:

```text
fix(seharden): preserve JSON errors for invalid format combinations
feat(rpm): include source commit in release bundles
docs(contributing): document review expectations
```

Accepted types include `build`, `chore`, `ci`, `docs`, `feat`, `feature`, `fix`,
`perf`, `refa`, `refactor`, `release`, `revert`, `style`, and `test`.

Every commit must include a signoff trailer:

```sh
git commit -s
```

## Pull Requests

PR descriptions should include:

- What changed and why.
- The user-visible, packaging, security, or compatibility impact.
- The validation commands that were actually run.
- Any contract, schema, or downstream consumer impact.

Use `no-issue: <reason>` in the PR body when there is no linked issue.
