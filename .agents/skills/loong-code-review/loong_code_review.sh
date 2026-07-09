#!/usr/bin/env bash

# Headless launcher for loong-code-review.
#
# Usage:
#   LCR_AGENT_PROFILE=codex .agents/skills/loong-code-review/loong_code_review.sh 'files README.md review.md'
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
[[ $# -eq 1 ]] || {
    echo "usage: loong_code_review.sh '<raw loong-code-review args>'" >&2
    exit 2
}

raw="$1"
prompt="Use the loong-code-review skill at $HERE with these exact arguments: $raw"
"$HERE/scripts/run_agent.sh" "$prompt"
