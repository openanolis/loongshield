#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/ci/check-commit-title.sh <title>

Accepted format:
  type: subject
  type(scope): subject
  type(scope)!: subject

Accepted types:
  build, chore, ci, docs, feat, feature, fix, perf, refa, refactor,
  release, revert, style, test
EOF
}

if (($# != 1)); then
    usage >&2
    exit 1
fi

title="$1"
pattern='^(build|chore|ci|docs|feat|feature|fix|perf|refa|refactor|release|revert|style|test)(\([a-z0-9._/-]+\))?!?: [^[:space:]].*$'

if [[ "$title" =~ $pattern ]]; then
    exit 0
fi

cat >&2 <<EOF
Error: invalid commit title:
  $title

Expected:
  type: subject
  type(scope): subject

Examples:
  fix: handle empty yaml input
  feature(ci): add commit title check
  refactor(seharden): simplify rule loader
EOF
exit 1
