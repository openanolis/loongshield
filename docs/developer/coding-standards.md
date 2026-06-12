# Loongshield Coding and Review Standards

This document is the shared reference for Loongshield contributors and AI coding
agents. This file is the source of truth for coding and review expectations.

## 1. Scope and Change Shape

- Keep changes small and reviewable. A PR should do one thing well.
- Do not mix unrelated cleanup with feature work or bug fixes.
- Match existing module boundaries before introducing a new abstraction.
- Prefer the simplest correct design that satisfies the current requirement.
- When a change spans several areas, split it by contract first, implementation second,
  and cleanup last.

## 2. AI Coding Agent Practices

AI coding agents should follow the same contribution rules as human contributors, with a
few extra guardrails:

- Read `CONTRIBUTING.md`, this file, and `docs/developer/build-and-test.md` before
  making non-trivial changes.
- Inspect the existing implementation and tests before proposing a design.
- State assumptions and tradeoffs when the request is ambiguous.
- Keep edits surgical. Do not reformat, refactor, or clean up unrelated code.
- Define success criteria before coding: which behavior changes, which tests prove it,
  and which docs or contracts must be updated.
- Prefer `rg` for caller and consumer searches.
- If a command cannot run in the current environment, record the reason and run the
  nearest useful check.
- Do not leave long-running dev servers, test processes, or package builds running when
  handing work back.

## 3. Public Contracts

Treat the following as stable contracts once documented:

- CLI commands, options, exit behavior, and examples in `docs/reference/`.
- Machine-readable CLI output such as `seharden --format json`.
- SEHarden profile format, rule fields, probe behavior, and reinforce semantics.
- RPM source bundle, spec macro, version, and commit metadata behavior.
- Installed paths and packaged files used by operators or downstream tooling.

Contract changes require all relevant pieces in the same PR:

- implementation update
- reference docs update
- unit or integration tests
- e2e tests when the process-level CLI behavior changes
- downstream consumer audit when another tool depends on the output

Machine-readable JSON must carry a `schema_version`. Add fields in a
backward-compatible way when possible. Removing fields, changing types, or changing
required semantics is a breaking contract change and must be called out explicitly.

Human-readable output is not a programmatic interface. Do not parse default text output
from other tools; add or consume a documented machine-readable format.

## 4. Caller and Consumer Impact

For any change to an existing function, module, CLI contract, profile schema, or RPM
metadata contract, check the global impact:

1. Find callers or consumers with `rg`, including tests, docs, scripts, CI, and known
   downstream integrations.
2. Verify signatures, return values, exceptions, side effects, and ordering assumptions.
3. Update affected callers in the same PR when the change is intentionally breaking.
4. Prefer backward-compatible extensions over breaking changes unless there is a clear
   reason.

This is especially important for `seharden` output because downstream tooling consumes it.

## 5. Documentation

Update documentation whenever behavior changes:

- Public command behavior: `docs/reference/loongshield-cli.md` or the relevant subcommand doc.
- SEHarden CLI behavior: `docs/reference/seharden-cli.md`.
- Profile schema and rule semantics: `docs/reference/seharden-profile-format.md`.
- Maintainer design rationale: `docs/design/`.
- Build, test, packaging, or release workflow: `docs/developer/`, `dist/`, or `RELEASING.md`.

Documentation should be concrete and include examples when syntax or data formats matter.
Explain important tradeoffs briefly so future maintainers understand why the behavior exists.

## 6. Coding Conventions

### C and Headers

- Use the existing C style and run `make fmt` or `make fmt-check`.
- Prefer explicit error handling and cleanup paths over runtime `assert` for user input,
  filesystem state, package metadata, or system calls.
- Release resources on every failure path: memory, file descriptors, handles, and temporary
  files.
- Keep public headers minimal. Do not expose internals just to make one call site easier.

### Lua

- Keep module APIs small and explicit.
- Prefer structured tables for structured data instead of ad hoc strings.
- Avoid hidden global state. If state is cached, document invalidation rules and test them.
- Return clear status and error values consistent with nearby modules.
- Use public module behavior in tests when practical; avoid binding tests to private helpers.

### YAML, Shell, and CI

- Keep profile and workflow changes focused and easy to diff.
- Use `set -euo pipefail` in new shell scripts or multi-line CI shell steps.
- Quote paths and variables unless word splitting is intentional.
- Use temporary directories and `trap` cleanup for scripts that create files.
- Do not modify vendored dependency content under `deps/` unless the task is explicitly about
  that dependency.

## 7. Tests

All behavior changes need tests at the right level:

- Bug fixes need regression tests that fail without the fix.
- New features need unit or integration coverage and e2e coverage for user-facing CLI flows.
- Contract changes need tests that check field names, types, required values, and failure
  behavior.
- Reinforce or system-mutating behavior must support dry-run or isolated fixtures where
  possible.

Test layout:

- `tests/unit/`: isolated module tests.
- `tests/integration/`: filesystem and system-behavior tests.
- `tests/e2e/`: process-level CLI tests.

Common commands:

```sh
make test-quick
make test-e2e
make test
```

For focused work, run targeted tests first and then broaden based on risk.

## 8. Formatting and Validation

Use project tooling:

```sh
make fmt
make fmt-check
git diff --check
```

CI also checks commit titles and signoff trailers. Use `git commit -s`.

## 9. Review Checklist

Before asking for review, verify:

- The change matches the PR description and does not include unrelated cleanup.
- Public contracts and downstream consumers were checked.
- Docs were updated for user-visible, schema, packaging, or release workflow changes.
- Tests were added or updated for changed behavior.
- Failure paths clean up partial state.
- No tool parses human-readable text output when a machine-readable format is available.
- `make fmt-check`, relevant tests, and `git diff --check` pass or skipped checks are explained.

Reviewers should prioritize correctness, contract stability, failure paths, test coverage,
and maintainability. Avoid nitpicks that are already handled by formatters or unrelated to
the changed lines.
