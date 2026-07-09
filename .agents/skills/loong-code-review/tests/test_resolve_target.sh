#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
SKILL="$ROOT/.agents/skills/loong-code-review"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

"$SKILL/scripts/resolve_target.sh" --meta 'files README.md:1-3,4 docs/README.md out.md --per-persona-context=no' > "$tmp/meta"
grep -qx 'mode=files' "$tmp/meta"
grep -qx 'files=README.md:1-4,docs/README.md' "$tmp/meta"
grep -qx 'output=out.md' "$tmp/meta"
grep -qx 'per_persona_context=no' "$tmp/meta"

"$SKILL/scripts/resolve_target.sh" 'files README.md:1-2 out.md' > "$tmp/input"
grep -qx '===== README.md lines 1-2 =====' "$tmp/input"
grep -q 'Loongshield' "$tmp/input"

if "$SKILL/scripts/resolve_target.sh" 'files NO_SUCH_FILE out.md' >"$tmp/bad" 2>"$tmp/err"; then
    echo "expected missing file to fail" >&2
    exit 1
fi
grep -q 'no such file' "$tmp/err"
