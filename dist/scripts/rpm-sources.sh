#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  rpm-sources.sh build --repo-root <path> --out-dir <path> --project <name> --version <version> [--manifest <path>]
  rpm-sources.sh list  --repo-root <path> --out-dir <path> --project <name> --version <version> [--manifest <path>]
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

command_name="${1:-}"
if [[ -z "${command_name}" ]]; then
    usage >&2
    exit 1
fi
shift

repo_root=""
out_dir=""
project=""
version=""
manifest=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-root)
            repo_root="${2:-}"
            shift 2
            ;;
        --out-dir)
            out_dir="${2:-}"
            shift 2
            ;;
        --project)
            project="${2:-}"
            shift 2
            ;;
        --version)
            version="${2:-}"
            shift 2
            ;;
        --manifest)
            manifest="${2:-}"
            shift 2
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

[[ -n "${repo_root}" ]] || die "--repo-root is required"
[[ -n "${out_dir}" ]] || die "--out-dir is required"
[[ -n "${project}" ]] || die "--project is required"
[[ -n "${version}" ]] || die "--version is required"

repo_root="$(cd "${repo_root}" && pwd)"
out_dir="$(mkdir -p "${out_dir}" && cd "${out_dir}" && pwd)"
manifest="${manifest:-${repo_root}/dist/rpm-vendor-sources.txt}"

[[ -f "${manifest}" ]] || die "manifest not found: ${manifest}"
[[ -f "${repo_root}/.gitmodules" ]] || die ".gitmodules not found under ${repo_root}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

main_archive="${out_dir}/${project}-${version}.tar.gz"

manifest_entries() {
    awk 'NF && $1 !~ /^#/ { print $1 "\t" $2 "\t" $3 }' "${manifest}"
}

list_archives() {
    printf '%s\n' "${main_archive}"
    manifest_entries | while IFS=$'\t' read -r base path commit; do
        printf '%s/%s-%s.tar.gz\n' "${out_dir}" "${base}" "${commit}"
    done
}

validate_manifest() {
    local manifest_paths gitmodule_paths

    manifest_paths="${tmpdir}/manifest.paths"
    gitmodule_paths="${tmpdir}/gitmodules.paths"

    manifest_entries | awk -F '\t' '{ print $2 }' | LC_ALL=C sort > "${manifest_paths}"
    git -C "${repo_root}" config -f .gitmodules --get-regexp '^submodule\..*\.path$' \
        | awk '{ print $2 }' \
        | LC_ALL=C sort > "${gitmodule_paths}"

    if ! diff -u "${gitmodule_paths}" "${manifest_paths}" > /dev/null; then
        diff -u "${gitmodule_paths}" "${manifest_paths}" >&2 || true
        die "vendor manifest does not match .gitmodules"
    fi

    manifest_entries | while IFS=$'\t' read -r base path commit; do
        local submodule_dir actual_commit
        submodule_dir="${repo_root}/${path}"
        [[ -d "${submodule_dir}" ]] || die "submodule path is missing: ${path}"
        actual_commit="$(git -C "${submodule_dir}" rev-parse HEAD 2>/dev/null)" \
            || die "failed to resolve commit for ${path}; initialize submodules first"
        if [[ "${actual_commit}" != "${commit}" ]]; then
            die "submodule ${path} is at ${actual_commit}, expected ${commit}; update dist/rpm-vendor-sources.txt and dist/loongshield.spec together"
        fi
    done
}

build_archive_from_filelist() {
    local base_dir="$1"
    local prefix="$2"
    local archive_path="$3"
    local filelist="$4"

    [[ -s "${filelist}" ]] || die "file list for ${archive_path} is empty"
    rm -f "${archive_path}"
    tar -C "${base_dir}" \
        --null \
        --no-recursion \
        -T "${filelist}" \
        --transform "s,^,${prefix}/," \
        -czf "${archive_path}"
}

build_main_archive() {
    local filelist
    local -a exclude_args

    filelist="${tmpdir}/source0.list"
    exclude_args=()

    while IFS=$'\t' read -r base path commit; do
        exclude_args+=(":(exclude)${path}")
    done < <(manifest_entries)

    git -C "${repo_root}" ls-files -z -- . "${exclude_args[@]}" > "${filelist}"
    build_archive_from_filelist "${repo_root}" "${project}-${version}" "${main_archive}" "${filelist}"
}

build_vendor_archives() {
    manifest_entries | while IFS=$'\t' read -r base path commit; do
        local filelist archive_path
        filelist="${tmpdir}/${base}.list"
        archive_path="${out_dir}/${base}-${commit}.tar.gz"
        git -C "${repo_root}/${path}" ls-files -z --recurse-submodules > "${filelist}"
        build_archive_from_filelist "${repo_root}/${path}" "${base}-${commit}" "${archive_path}" "${filelist}"
    done
}

case "${command_name}" in
    build)
        validate_manifest
        build_main_archive
        build_vendor_archives
        ;;
    list)
        list_archives
        ;;
    *)
        usage >&2
        die "unknown command: ${command_name}"
        ;;
esac
