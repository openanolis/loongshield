#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tools/ci/check-commit-title.sh <title>
  tools/ci/check-commit-title.sh --title <title> --body-file <path>

Accepted format:
  type: subject
  type(scope): subject
  type(scope)!: subject

Accepted types:
  build, chore, ci, docs, feat, feature, fix, perf, refa, refactor,
  release, revert, style, test

Required trailer:
  Signed-off-by: Name <email@example.com>
EOF
}

title=""
body_file=""

if (($# == 1)); then
    title="$1"
else
    while (($# > 0)); do
        case "$1" in
            --title)
                title="${2:-}"
                shift 2
                ;;
            --body-file)
                body_file="${2:-}"
                shift 2
                ;;
            *)
                usage >&2
                exit 1
                ;;
        esac
    done
fi

if [[ -z "$title" ]]; then
    usage >&2
    exit 1
fi

pattern='^(build|chore|ci|docs|feat|feature|fix|perf|refa|refactor|release|revert|style|test)(\([a-z0-9._/-]+\))?!?: [^[:space:]].*$'

if ! [[ "$title" =~ $pattern ]]; then
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
fi

if [[ -n "$body_file" ]]; then
    if [[ ! -f "$body_file" ]]; then
        echo "Error: commit body file not found: $body_file" >&2
        exit 1
    fi

    if ! grep -Eq '^Signed-off-by: .+ <.+>$' "$body_file"; then
        cat >&2 <<EOF
Error: missing Signed-off-by trailer:
  $title

Expected trailer:
  Signed-off-by: Name <email@example.com>

Tip:
  use 'git commit -s'
EOF
        exit 1
    fi
fi
