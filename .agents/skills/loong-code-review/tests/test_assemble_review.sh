#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
SKILL="$ROOT/.agents/skills/loong-code-review"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/meta" <<EOF
date=2026-07-03
mode=files
files=README.md:1-2
head=test
branch=test-branch
EOF

cat > "$tmp/frags.tmp" <<'EOF'
[{"file":"README.md","line":1,"persona":"correctness","grounding":"preserve-cli-contract","severity":"major","problem":"`README.md` example no longer matches the CLI.","fix":"Update the example to use the current command syntax.","diff":"- old\n+ new"}]
EOF
mkdir "$tmp/frags"
cp "$tmp/frags.tmp" "$tmp/frags/correctness.json"

"$SKILL/scripts/assemble_review.sh" "$tmp/meta" "$tmp/frags" "$tmp/review.md" 2>"$tmp/assemble.err"

grep -q 'assemble: maintainability=0, correctness=1, security=0, documentation=0' "$tmp/assemble.err"
grep -q '^# Summary$' "$tmp/review.md"
grep -q '^## Correctness$' "$tmp/review.md"
grep -q '`preserve-cli-contract` (major): `README.md` example no longer matches the CLI.' "$tmp/review.md"

if "$SKILL/scripts/assemble_review.sh" "$tmp/meta" "$tmp/frags" "$tmp/review.md" 2>"$tmp/clobber.err"; then
    echo "expected overwrite refusal" >&2
    exit 1
fi
grep -q 'refusing to overwrite' "$tmp/clobber.err"
