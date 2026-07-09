#!/usr/bin/env bash

# build_pass_prompt.sh -- assemble a deterministic persona pass prompt.
#
# Usage: build_pass_prompt.sh <input-file> <persona> [<persona> ...]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SKILLDIR="$(cd "$HERE/.." && pwd)"

input="${1:-}"
shift || true
[[ -n "$input" && -f "$input" ]] || {
    echo "build_pass_prompt.sh: a readable <input-file> is required" >&2
    exit 2
}
[[ $# -ge 1 ]] || {
    echo "build_pass_prompt.sh: at least one <persona> is required" >&2
    exit 2
}

cat "$SKILLDIR/scripts/pass_contract.md"
printf '\n'

for persona in "$@"; do
    pf="$SKILLDIR/personas/$persona.md"
    [[ -f "$pf" ]] || {
        echo "build_pass_prompt.sh: no such persona: $persona" >&2
        exit 2
    }
    printf '===== PERSONA: %s =====\n\n' "$persona"
    cat "$pf"
    printf '\n'
done

printf '===== REVIEW INPUT =====\n\n'
cat "$input"
