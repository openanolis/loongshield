# loong-code-review

A local agent review flow for LoongShield, modeled on Asterinas'
`aster-code-review` structure and adapted to this repository's C/Lua host-security
surface.

It reviews either a committed branch diff or selected files, runs persona-focused
review passes, and writes a single Markdown review file.

## Usage

Trigger it from an agent session:

```text
Use loong-code-review to review this branch over main into review.md.
Use loong-code-review to review files src/daemon/main.c docs/reference/loongshield-cli.md into review.md.
```

Raw interface:

```sh
diff <base> <output> [--overwrite]
files <path[:lines] ...> <output> [--overwrite]
```

## Contents

| Path | Purpose |
|---|---|
| `SKILL.md` | Agent-facing orchestration instructions. |
| `personas/` | LoongShield maintainability, correctness, security, and documentation review guidance. |
| `scripts/` | Deterministic target parsing, pass prompt construction, review assembly, and agent launching. |
| `agent_profiles/` | Headless launcher profiles. |
| `tests/` | Script-level smoke tests. |

Run deterministic checks with:

```sh
make -C .agents/skills/loong-code-review test
```
