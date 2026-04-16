#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/format/run.sh <write|check> [files...]

When no files are provided, only changed first-party Lua, C, header, and YAML
files are processed.
EOF
}

mode="${1:-}"
if [[ -z "$mode" ]]; then
    usage >&2
    exit 1
fi
shift || true

if [[ "$mode" != "write" && "$mode" != "check" ]]; then
    usage >&2
    exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

stylua_config="${repo_root}/tools/format/stylua.toml"
clang_format_config="${repo_root}/tools/format/clang-format.yaml"

declare -A seen=()
declare -a files=()

is_format_file() {
    case "$1" in
        deps/*|dist/*|build/*)
            return 1
            ;;
        src/daemon/bin_initrd_tar.h|src/daemon/bin_ramfs_luac.h)
            return 1
            ;;
        *.lua|*.c|*.h|*.yml|*.yaml)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

append_file() {
    local path="$1"

    if ! is_format_file "$path"; then
        return
    fi
    if [[ ! -f "$path" ]]; then
        return
    fi
    if [[ -n "${seen[$path]:-}" ]]; then
        return
    fi

    seen["$path"]=1
    files+=("$path")
}

collect_default_files() {
    local path

    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        return
    fi

    if git rev-parse --verify HEAD >/dev/null 2>&1; then
        while IFS= read -r -d '' path; do
            append_file "$path"
        done < <(git diff --name-only -z --diff-filter=ACMR HEAD -- 2>/dev/null || true)
    fi

    while IFS= read -r -d '' path; do
        append_file "$path"
    done < <(git diff --name-only -z --diff-filter=ACMR -- 2>/dev/null || true)

    while IFS= read -r -d '' path; do
        append_file "$path"
    done < <(git ls-files --others --exclude-standard -z 2>/dev/null || true)
}

collect_explicit_files() {
    local path

    for path in "$@"; do
        append_file "$path"
    done
}

require_tool() {
    local tool="$1"
    local hint="$2"

    if command -v "$tool" >/dev/null 2>&1; then
        return
    fi

    echo "Error: '$tool' was not found in PATH." >&2
    echo "$hint" >&2
    exit 1
}

find_clang_format() {
    local candidate

    for candidate in \
        "${CLANG_FORMAT_BIN:-}" \
        clang-format \
        clang-format-20 \
        clang-format-19 \
        clang-format-18 \
        clang-format-17 \
        clang-format-16 \
        clang-format-15 \
        clang-format-14 \
        clang-format-13; do
        if [[ -n "$candidate" ]] && command -v "$candidate" >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

run_step() {
    local label="$1"
    shift

    echo "==> $label"
    if ! "$@"; then
        return 1
    fi
}

if (($# > 0)); then
    collect_explicit_files "$@"
else
    collect_default_files
fi

if ((${#files[@]} == 0)); then
    echo "No Lua, C, or YAML files to ${mode}."
    exit 0
fi

declare -a lua_files=()
declare -a c_files=()
declare -a yaml_files=()

for path in "${files[@]}"; do
    case "$path" in
        *.lua)
            lua_files+=("$path")
            ;;
        *.c|*.h)
            c_files+=("$path")
            ;;
        *.yml|*.yaml)
            yaml_files+=("$path")
            ;;
    esac
done

status=0
clang_format_bin=""

if ((${#lua_files[@]} > 0)); then
    require_tool stylua "Install StyLua manually and ensure it is available in PATH."
    if [[ "$mode" == "write" ]]; then
        run_step "StyLua (${#lua_files[@]} file(s))" \
            stylua --config-path "$stylua_config" "${lua_files[@]}" || status=1
    else
        run_step "StyLua (${#lua_files[@]} file(s))" \
            stylua --config-path "$stylua_config" --check --output-format=summary "${lua_files[@]}" || status=1
    fi
fi

if ((${#c_files[@]} > 0)); then
    clang_format_bin="$(find_clang_format || true)"
    if [[ -z "$clang_format_bin" ]]; then
        echo "Error: 'clang-format' was not found in PATH." >&2
        echo "Install LLVM clang-format locally, or set CLANG_FORMAT_BIN to a versioned binary." >&2
        exit 1
    fi
    if [[ "$mode" == "write" ]]; then
        run_step "clang-format (${#c_files[@]} file(s))" \
            "$clang_format_bin" -style="file:${clang_format_config}" -i "${c_files[@]}" || status=1
    else
        run_step "clang-format (${#c_files[@]} file(s))" \
            "$clang_format_bin" -style="file:${clang_format_config}" --dry-run --Werror "${c_files[@]}" || status=1
    fi
fi

if ((${#yaml_files[@]} > 0)); then
    require_tool yamlfmt "Install yamlfmt manually and ensure it is available in PATH."
    if [[ "$mode" == "write" ]]; then
        run_step "yamlfmt (${#yaml_files[@]} file(s))" yamlfmt "${yaml_files[@]}" || status=1
    else
        run_step "yamlfmt (${#yaml_files[@]} file(s))" yamlfmt -lint "${yaml_files[@]}" || status=1
    fi
fi

exit "$status"
