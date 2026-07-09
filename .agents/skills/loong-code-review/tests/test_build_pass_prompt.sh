#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
SKILL="$ROOT/.agents/skills/loong-code-review"
tmp="$(mktemp)"
trap 'rm -f "$tmp" "$tmp.out"' EXIT

printf '===== README.md =====\n     1\t# Loongshield\n' > "$tmp"
"$SKILL/scripts/build_pass_prompt.sh" "$tmp" correctness security > "$tmp.out"

grep -q '^# Pass Contract$' "$tmp.out"
grep -q '^===== PERSONA: correctness =====$' "$tmp.out"
grep -q '^===== PERSONA: security =====$' "$tmp.out"
grep -q '^===== REVIEW INPUT =====$' "$tmp.out"
grep -q '# Loongshield' "$tmp.out"
