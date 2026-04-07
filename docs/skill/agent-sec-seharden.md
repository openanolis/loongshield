---
name: agentos-baseline
description: Use the only supported Phase 1 flow: `loongshield seharden --config agentos_baseline`.
---

# Phase 1: SEHarden

Unless the user explicitly asks for another language, keep operator-facing output in English.

## Fixed Baseline

Phase 1 only supports this baseline:

- Tool: `loongshield seharden`
- Profile: `agentos_baseline`

Do not switch to another profile.
Do not replace this flow with another shell script, wrapper, or hardening tool.

## Modes

Read `$ARGUMENTS` and map it to one of these modes:

- Empty or `scan`
- `dry-run`
- `reinforce`

If `$ARGUMENTS` is anything else, stop and tell the user:

```text
Supported modes: scan | dry-run | reinforce
```

## Exact Commands

- `scan`: `loongshield seharden --scan --config agentos_baseline`
- `dry-run`: `loongshield seharden --reinforce --dry-run --config agentos_baseline`
- `reinforce`: `loongshield seharden --reinforce --config agentos_baseline`

Always keep `--config agentos_baseline` explicit.

## Execution Rules

1. Verify `loongshield` is installed before running anything.
2. Never run `reinforce` unless the user explicitly requested it.
3. `reinforce` requires root. Do not add `sudo` silently.
4. Run only the selected `loongshield seharden` command.
5. Show the command output directly.

## Result Handling

Treat the run as non-compliant if either of these is true:

- the command exits non-zero
- the output contains `FAIL`, `MANUAL`, `DRY-RUN`, `FAILED-TO-FIX`, `ENFORCE-ERROR`, or `Engine Error`

Use a short report:

- success: `Result: compliant`
- failure: `Result: non-compliant`

If `scan` is non-compliant, add:

```text
Suggestion: run `dry-run` first to preview the changes, then run `reinforce` if you want to apply them.
```

If `dry-run` is non-compliant, add:

```text
Suggestion: after reviewing the dry-run result, you can run `reinforce`.
```

If `reinforce` succeeds, say the baseline has been applied successfully.
