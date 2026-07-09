---
name: loong-code-review
description: Review LoongShield Git changes or target files using persona-keyed guidance and write a Markdown review file. Use when asked to review a branch, commit series, diff from a base ref, or specific LoongShield files for correctness, security, maintainability, documentation, or missing tests.
---

# loong-code-review

Review LoongShield code and docs through four personas, then write one Markdown
review file. The review is recall-first: miss as few real defects as possible,
while verifying comments before finalizing.

There are two modes, both anchored at the current checkout:

- `diff <base>` reviews committed commits in `merge-base(<base>, HEAD)..HEAD`.
  Commit first; uncommitted edits are not reviewed in diff mode.
- `files <path[:lines] ...>` reviews working-tree file contents, optionally
  narrowed to line ranges.

## Interface

The skill receives one raw argument string beginning with a mode word:

```sh
diff   <base>              <output> [--overwrite] [--per-persona-context=auto|yes|no]
files  <path[:lines] ...>  <output> [--overwrite] [--per-persona-context=auto|yes|no]
```

- `<output>` is required and is the last positional argument.
- `--overwrite` allows replacing an existing output file.
- `--per-persona-context=auto|yes|no` controls fan-out. `auto` currently means `yes`.
- Pass the raw argument string as one quoted argument to `resolve_target.sh`; do not split it yourself.

Example:

```sh
SKILL="$(git rev-parse --show-toplevel)/.agents/skills/loong-code-review"
"$SKILL/scripts/resolve_target.sh" 'files src/daemon/main.c:1-120 review.md'
```

## Pipeline

Invoke helper scripts by absolute path from the repo root:

```sh
SKILL="$(git rev-parse --show-toplevel)/.agents/skills/loong-code-review"
```

1. Resolve target:
   - `"$SKILL/scripts/resolve_target.sh" --meta '<raw args>' > "$meta"`
   - Add `date=YYYY-MM-DD` to the meta file.
   - `"$SKILL/scripts/resolve_target.sh" '<raw args>' > "$input"`
2. Activate personas from reviewed paths.
3. Build each pass prompt with `"$SKILL/scripts/build_pass_prompt.sh" "$input" <persona>...`.
4. Spawn persona passes.
5. Save each pass JSON array as `<fragdir>/<persona>.json`.
6. Assemble with `"$SKILL/scripts/assemble_review.sh" [--overwrite] "$meta" "$fragdir" "$output"`.
7. Verify every comment. Remove only confidently refuted comments; prefix uncertain comments with `(unverified) ` in `problem`.
8. Consolidate comments that share one root cause by pointing their fixes at the shared remedy.
9. Replace `<!-- SUMMARY -->` with a concise summary of strengths, top issues by severity, and structural recommendations.

## Activation

Reviewed paths are changed paths in `diff` mode and named paths in `files` mode.

- `maintainability`: all first-party changes.
- `correctness`: all first-party code, tests, build, packaging, profiles, and generated asset changes.
- `security`: all first-party changes, because LoongShield is host-security tooling. Emphasize `src/kmod`, `src/daemon/lua_*`, `profiles/`, `dist/`, filesystem, RPM, systemd, dbus, securityfs, and network/SBOM paths.
- `documentation`: any `*.md`, `docs/`, `README`, `CHANGELOG.md`, `RELEASING.md`, or change to user-visible CLI, profile semantics, packaging, install paths, output contracts, or release flow.

Skip `deps/` unless the review target explicitly names vendored code.

Use path rules deterministically. Do not let the model decide whether a persona is needed.

## Spawning

Default fan-out (`auto` or `yes`) runs one isolated pass per activated persona.
Combined mode (`no`) builds one prompt with all activated personas and runs one pass.

For Codex, spawn a pass with the exact output of `build_pass_prompt.sh`:

```sh
prompt="$("$SKILL/scripts/build_pass_prompt.sh" "$input" correctness)"
codex exec "$prompt" > "$fragdir/correctness.json"
```

Do not spawn a pass by re-running `loong_code_review.sh` or `run_agent.sh` from
inside the skill. A persona pass receives a built prompt, not the skill arguments.

## Verification

For each comment, isolate the premise and try to refute it by rereading the cited
code and relevant docs or authoritative platform references. Assign:

- `confirmed`: keep the comment unchanged.
- `uncertain`: keep it, but prefix `problem` with `(unverified) `.
- `refuted`: remove it and add a `## Retracted by verification` note with a one-line reason.

Remove only on confident refutation.

## Output Format

The assembled review contains YAML frontmatter, `# Summary`, then persona sections
in this order: Maintainability, Correctness, Security, Documentation.

Each comment is a `###` location heading, an optional diff snippet, a severity line,
and a `**Fix.**` paragraph. Do not restructure the assembled file except for
verification, consolidation, and replacing the summary placeholder.
