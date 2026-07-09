#!/usr/bin/env bash

# run_agent.sh -- launch the LCR_AGENT_PROFILE agent with one prompt.
#
# Usage: run_agent.sh "<prompt>"
# Env:
#   LCR_AGENT_PROFILE    profile name under agent_profiles/ or a profile dir
#   LCR_PROFILE_VARIANT  smoke to merge profile.smoke.json/config.smoke.toml
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SKILL="$(cd "$HERE/.." && pwd)"
profiles_dir="$SKILL/agent_profiles"

[[ $# -eq 1 ]] || {
    echo "usage: run_agent.sh \"<prompt>\"" >&2
    exit 2
}
prompt="$1"

if [[ -n "${LCR_AGENT_RUNNING:-}" ]]; then
    echo "run_agent.sh: refusing recursive launcher entry; spawn persona passes with build_pass_prompt.sh output instead" >&2
    exit 3
fi
export LCR_AGENT_RUNNING=1

list_profiles() {
    find "$profiles_dir" -mindepth 2 -maxdepth 2 -name profile.json -printf '%h\n' 2>/dev/null |
        xargs -r -n1 basename | sort | tr '\n' ' '
}

[[ -n "${LCR_AGENT_PROFILE:-}" ]] || {
    echo "run_agent.sh: LCR_AGENT_PROFILE is required (for example, LCR_AGENT_PROFILE=codex). Available: $(list_profiles)" >&2
    exit 2
}

if [[ "$LCR_AGENT_PROFILE" == */* ]]; then
    PROFILE_DIR="$LCR_AGENT_PROFILE"
else
    PROFILE_DIR="$profiles_dir/$LCR_AGENT_PROFILE"
fi
[[ -f "$PROFILE_DIR/profile.json" ]] || {
    echo "run_agent.sh: profile not found: $PROFILE_DIR/profile.json (available: $(list_profiles))" >&2
    exit 2
}
PROFILE_DIR="$(cd "$PROFILE_DIR" && pwd)"
PROFILE_SMOKE=0
[[ "${LCR_PROFILE_VARIANT:-}" == smoke ]] && PROFILE_SMOKE=1
PROFILE_WORKDIR="$(mktemp -d)"
trap 'rm -rf "$PROFILE_WORKDIR"' EXIT
declare -a PROFILE_CMD=() PROFILE_ENV=() INH_SRC=() INH_DEST=()

profile_parsed="$(python3 - "$PROFILE_DIR" "$PROFILE_WORKDIR" "$HOME" "$PROFILE_SMOKE" <<'PY'
import json
import os
import sys

pdir, workdir, home, smoke = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1"

def load_json(p):
    if not os.path.exists(p):
        return {}
    try:
        return json.load(open(p))
    except Exception as e:
        sys.stderr.write(f"invalid JSON {p}: {e}\n")
        sys.exit(3)

prof = load_json(os.path.join(pdir, "profile.json"))
if smoke:
    prof.update(load_json(os.path.join(pdir, "profile.smoke.json")))
cmd = prof.get("command")
if not isinstance(cmd, list) or not cmd or not all(isinstance(x, str) for x in cmd):
    sys.stderr.write("profile 'command' must be a non-empty array of strings\n")
    sys.exit(3)

def sub(s):
    return str(s).replace("{workdir}", workdir).replace("{home}", home)

for t in cmd:
    print("C\t" + sub(t))
for k, v in (prof.get("env") or {}).items():
    print("E\t" + f"{k}={sub(v)}")
for src, dest in (prof.get("inherit") or {}).items():
    print("I\t" + sub(str(src)) + "\t" + sub(dest))

def toml_flat(p):
    d = {}
    if os.path.exists(p):
        for ln in open(p):
            s = ln.strip()
            if s.startswith("["):
                break
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                d[k.strip()] = v.strip()
    return d

def toml_tables(p):
    out, started = [], False
    if os.path.exists(p):
        for ln in open(p):
            if not started and ln.lstrip().startswith("["):
                started = True
            if started:
                out.append(ln.rstrip("\n"))
    return out

base = os.path.join(pdir, "config.toml")
if os.path.exists(base):
    cfg, tables = toml_flat(base), toml_tables(base)
    if smoke:
        smk = os.path.join(pdir, "config.smoke.toml")
        cfg.update(toml_flat(smk))
        st = toml_tables(smk)
        if st:
            tables = st
    with open(os.path.join(workdir, "config.toml"), "w") as f:
        for k, v in cfg.items():
            f.write(f"{k} = {v}\n")
        if tables:
            f.write("\n" + "\n".join(tables) + "\n")
PY
)" || {
    echo "run_agent.sh: invalid profile: $PROFILE_DIR" >&2
    exit 2
}

while IFS=$'\t' read -r tag a b; do
    case "$tag" in
        C) PROFILE_CMD+=("$a") ;;
        E) PROFILE_ENV+=("$a") ;;
        I) INH_SRC+=("$a"); INH_DEST+=("$b") ;;
    esac
done <<< "$profile_parsed"

for i in "${!INH_SRC[@]}"; do
    src="${INH_SRC[$i]}"
    dest="$PROFILE_WORKDIR/${INH_DEST[$i]}"
    [[ -f "$src" ]] || {
        echo "run_agent.sh: profile 'inherit' source not found: $src" >&2
        exit 2
    }
    mkdir -p "$(dirname "$dest")"
    cp "$src" "$dest"
done

declare -a argv=()
for tok in "${PROFILE_CMD[@]}"; do
    argv+=("${tok//\{prompt\}/$prompt}")
done

if [[ ${#PROFILE_ENV[@]} -gt 0 ]]; then
    env "${PROFILE_ENV[@]}" "${argv[@]}" </dev/null
else
    "${argv[@]}" </dev/null
fi
