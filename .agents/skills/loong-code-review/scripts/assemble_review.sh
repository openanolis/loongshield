#!/usr/bin/env bash

# assemble_review.sh -- merge persona JSON fragments into one Markdown review.
#
# Usage: assemble_review.sh [--overwrite] <meta-file> <frag-dir> <output-file>
set -euo pipefail

overwrite=0
pos=()
for a in "$@"; do
    case "$a" in
        --overwrite) overwrite=1 ;;
        --*) echo "assemble_review.sh: unknown flag: $a" >&2; exit 2 ;;
        *) pos+=("$a") ;;
    esac
done

if [[ ${#pos[@]} -ne 3 ]]; then
    echo "usage: assemble_review.sh [--overwrite] <meta-file> <frag-dir> <output-file>" >&2
    exit 2
fi

meta="${pos[0]}"
fragdir="${pos[1]}"
out="${pos[2]}"

if [[ -e "$out" && $overwrite -eq 0 ]]; then
    echo "assemble_review.sh: refusing to overwrite existing $out (pass --overwrite)" >&2
    exit 1
fi

python3 - "$meta" "$fragdir" "$out" <<'PY'
import json
import os
import re
import sys

meta_path, fragdir, out = sys.argv[1], sys.argv[2], sys.argv[3]
KEBAB = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")

def grounding_tag(g):
    return "`%s`" % g if KEBAB.fullmatch(str(g)) else str(g)

meta = {}
for line in open(meta_path):
    line = line.strip()
    if "=" in line:
        k, v = line.split("=", 1)
        meta[k] = v

ORDER = [
    ("maintainability", "Maintainability"),
    ("correctness", "Correctness"),
    ("security", "Security"),
    ("documentation", "Documentation"),
]

def load(persona):
    p = os.path.join(fragdir, persona + ".json")
    if not os.path.exists(p):
        return []
    try:
        data = json.load(open(p))
    except Exception as e:
        sys.stderr.write(f"assemble: FATAL: unparseable fragment {p}: {e}\n")
        sys.exit(2)
    if not isinstance(data, list):
        sys.stderr.write(f"assemble: FATAL: fragment {p} is not a JSON array of comments\n")
        sys.exit(2)
    return data

L = [
    "---",
    f"date: {meta.get('date', '')}",
    f"mode: {meta.get('mode', 'diff')}",
]
if meta.get("base"):
    L.append(f"base: {meta['base']}")
if meta.get("files"):
    L.append(f"files: {meta['files']}")
L += [
    f"head: {meta.get('head', '')}",
    f"branch: {meta.get('branch', '')}",
]
if meta.get("title"):
    L.append("title: " + json.dumps(meta["title"]))
L += ["---", "", "# Summary", "", "<!-- SUMMARY -->", ""]

counts = {}
for persona, title in ORDER:
    seen = set()
    uniq = []
    for c in load(persona):
        key = json.dumps(c, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    counts[persona] = len(uniq)
    if not uniq:
        continue
    uniq.sort(key=lambda c: (
        str(c.get("file", "")),
        int(c.get("line", 0) or 0),
        str(c.get("grounding", "")),
        str(c.get("problem", "")),
    ))
    L += [f"## {title}", ""]
    for c in uniq:
        loc = "`%s`" % c.get("file", "?")
        if c.get("line"):
            loc += " line %s" % c["line"]
        L += [f"### {loc}", ""]
        diff = c.get("diff")
        if diff:
            L.append("> ```diff")
            L += ["> " + dl for dl in str(diff).splitlines()]
            L += ["> ```", ""]
        L.append("%s (%s): %s" % (
            grounding_tag(c.get("grounding", "issue")),
            c.get("severity", "major"),
            (c.get("problem", "") or "").strip(),
        ))
        L += ["", "**Fix.** %s" % (c.get("fix", "") or "").strip(), ""]

open(out, "w").write("\n".join(L).rstrip() + "\n")
sys.stderr.write("assemble: " + ", ".join(f"{p}={counts[p]}" for p, _ in ORDER) + "\n")
PY
