#!/usr/bin/env bash

# resolve_target.sh -- parse a loong-code-review argument string and emit
# either canonical review input or frontmatter metadata.
#
# Usage:
#   resolve_target.sh        '<raw args>'
#   resolve_target.sh --meta '<raw args>'
#
# Raw argument grammar:
#   diff   <base>              <output> [--overwrite] [--per-persona-context=auto|yes|no]
#   files  <path[:lines] ...>  <output> [--overwrite] [--per-persona-context=auto|yes|no]
set -euo pipefail

meta=0
if [[ "${1:-}" == "--meta" ]]; then
    meta=1
    shift
fi
raw="${1-}"

parse="$(RAW="$raw" python3 - <<'PY'
import os
import re
import sys

raw = os.environ.get("RAW", "")

def fail(msg):
    sys.stderr.write("resolve_target.sh: " + msg + "\n")
    sys.exit(2)

def tokenize(s):
    toks, cur, inq, has = [], "", False, False
    for ch in s:
        if ch == '"':
            inq = not inq
            cur += ch
            has = True
        elif ch.isspace() and not inq:
            if has:
                toks.append(cur)
                cur, has = "", False
        else:
            cur += ch
            has = True
    if inq:
        fail("unbalanced double quote in arguments")
    if has:
        toks.append(cur)
    return toks

RANGES_RE = re.compile(r'^\d+(-\d+)?(,\d+(-\d+)?)*$')

def parse_ranges(spec):
    out = []
    for part in spec.split(','):
        if '-' in part:
            a, b = part.split('-', 1)
            a, b = int(a), int(b)
        else:
            a = b = int(part)
        if a < 1 or b < a:
            fail("invalid line range: " + part)
        out.append((a, b))
    out.sort()
    merged = [list(out[0])]
    for a, b in out[1:]:
        if a <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return ",".join(f"{a}-{b}" for a, b in merged)

def parse_target(tok):
    if tok.startswith('"'):
        end = tok.find('"', 1)
        if end == -1:
            fail("unterminated quote in: " + tok)
        path, rest = tok[1:end], tok[end + 1:]
        if rest == "":
            return path, ""
        if rest.startswith(':') and RANGES_RE.match(rest[1:]):
            return path, parse_ranges(rest[1:])
        fail("unexpected text after quoted path: " + rest)
    i = tok.rfind(':')
    if i != -1 and RANGES_RE.match(tok[i + 1:]):
        return tok[:i], parse_ranges(tok[i + 1:])
    return tok, ""

toks = tokenize(raw)
overwrite, app, pos = 0, "auto", []
for t in toks:
    if t == "--overwrite":
        overwrite = 1
    elif t.startswith("--per-persona-context="):
        app = t.split("=", 1)[1]
        if app not in ("auto", "yes", "no"):
            fail("--per-persona-context must be auto, yes, or no")
    elif t.startswith("--"):
        fail("unknown flag: " + t)
    else:
        pos.append(t)

if not pos:
    fail("missing mode word (diff|files)")
mode, rest = pos[0], pos[1:]
if mode not in ("diff", "files"):
    fail("unknown mode: " + mode + " (expected diff|files)")
if len(rest) < 2:
    fail(mode + ": need at least a target and an <output> path")

out_path, out_rng = parse_target(rest[-1])
if out_rng:
    fail("the <output> path must not carry a line range")
targets = rest[:-1]

lines = [("MODE", mode), ("OUTPUT", out_path), ("OVERWRITE", str(overwrite)), ("APP", app)]
if mode == "diff":
    if len(targets) != 1:
        fail("diff: exactly one <base> is required")
    base, brng = parse_target(targets[0])
    if brng:
        fail("diff: <base> must not carry a line range")
    if ".." in base:
        fail("diff takes a single <base>; check out the head, then use 'diff <base>'")
    lines.append(("BASE", base))
else:
    seen = {}
    order = []
    for t in targets:
        p, r = parse_target(t)
        if p not in seen:
            seen[p] = []
            order.append(p)
        if r:
            seen[p].append(r)
    for p in order:
        merged = parse_ranges(",".join(seen[p])) if seen[p] else ""
        lines.append(("TARGET", p + "\t" + merged))

for k, v in lines:
    print(k + "\t" + v)
PY
)"

mode=""; output=""; overwrite=0; base=""; app="auto"
tpath=(); tranges=()
while IFS=$'\t' read -r key a b; do
    case "$key" in
        MODE) mode="$a" ;;
        OUTPUT) output="$a" ;;
        OVERWRITE) overwrite="$a" ;;
        APP) app="$a" ;;
        BASE) base="$a" ;;
        TARGET) tpath+=("$a"); tranges+=("$b") ;;
    esac
done <<< "$parse"

cd "$(git rev-parse --show-toplevel)"

short() { git rev-parse --short "$1"; }

head_token="$(short HEAD)"
if [[ "$mode" == "files" ]] && { ! git diff --quiet || ! git diff --cached --quiet; }; then
    head_token="${head_token}-dirty"
fi

if [[ "$mode" == "diff" ]]; then
    mb="$(git merge-base "$base" HEAD)"
fi

if [[ $meta -eq 1 ]]; then
    printf 'mode=%s\n' "$mode"
    if [[ "$mode" == "diff" ]]; then
        printf 'base=%s\n' "$(short "$mb")"
    else
        files=""
        for i in "${!tpath[@]}"; do
            f="${tpath[$i]}"
            [[ -n "${tranges[$i]}" ]] && f="${f}:${tranges[$i]}"
            files+="${files:+,}$f"
        done
        printf 'files=%s\n' "$files"
    fi
    printf 'head=%s\n' "$head_token"
    printf 'branch=%s\n' "$(git rev-parse --abbrev-ref HEAD)"
    printf 'output=%s\n' "$output"
    printf 'overwrite=%s\n' "$overwrite"
    printf 'per_persona_context=%s\n' "$app"
    exit 0
fi

if [[ "$mode" == "diff" ]]; then
    if [[ -z "$(git rev-list "$mb..HEAD" 2>/dev/null)" ]]; then
        echo "resolve_target.sh: no commits in ${base}..HEAD - commit your changes first" >&2
        exit 2
    fi
    git log -p --reverse --no-color \
        --format='%n===== commit %h =====%n%n[commit message]%n%B%n[changes]%n' "$mb..HEAD"
else
    for i in "${!tpath[@]}"; do
        f="${tpath[$i]}"
        r="${tranges[$i]}"
        if [[ ! -f "$f" ]]; then
            echo "resolve_target.sh: no such file in the working tree: $f" >&2
            exit 2
        fi
        if [[ -z "$r" ]]; then
            printf '===== %s =====\n' "$f"
            awk '{printf "%6d\t%s\n", NR, $0}' "$f"
            printf '\n'
        else
            IFS=',' read -ra parts <<< "$r"
            for rg in "${parts[@]}"; do
                a="${rg%-*}"
                b="${rg#*-}"
                printf '===== %s lines %s-%s =====\n' "$f" "$a" "$b"
                awk -v a="$a" -v b="$b" 'NR>=a && NR<=b {printf "%6d\t%s\n", NR, $0}' "$f"
                printf '\n'
            done
        fi
    done
fi
