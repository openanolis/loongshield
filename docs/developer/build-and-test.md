# Build And Test

This page is for contributors working on Loongshield itself. Operator-facing usage lives in `docs/reference/`.

## Build Requirements

Loongshield is currently built and CI-checked on RPM-based Linux environments such as Anolis OS and Fedora. If your host is not compatible, use the Docker workflow in `docs/developer/docker-development.md`.

For a fresh local checkout on a compatible host, use the one-shot bootstrap target:

```sh
make bootstrap
```

This installs the required packages, initializes submodules, and runs the default build.

If you prefer to run each step manually, install the required toolchain and development headers with:

```sh
make buildreqs
```

You can also install packages directly with `dnf` or `yum`:

```sh
dnf install -y \
  git cmake gcc gcc-c++ make \
  perl perl-IPC-Cmd perl-FindBin which \
  NetworkManager-libnm-devel audit-libs-devel dbus-devel \
  elfutils-libelf-devel libarchive-devel libattr-devel \
  libcurl-devel libmount-devel libpsl-devel libyaml-devel \
  libcap-devel libzstd-devel openssl-devel rpm-devel \
  systemd-devel xz-devel
```

Then initialize submodules and build:

```sh
git submodule update --init --recursive
make
```

If you are auditing where vendored dependencies come from, see
`docs/developer/submodule-sources.md` for the current fork policy and the
submodules that still intentionally point at public forks.

## Core Commands

```sh
make
make test
make test-quick
make rpm
make rpm-in-docker
```

`make test` builds first and then runs the full Lua suite. `make test-quick` reuses the current build output and is the fastest way to rerun the full test suite after Lua-only or documentation changes.

## Test Layout

- `tests/unit/`: fast isolated module tests
- `tests/integration/`: filesystem and system-behavior tests
- `tests/e2e/`: reserved for full-flow suites; some revisions may not yet carry checked-in e2e cases
- `tests/run.lua`: custom test discovery and runner

## Documentation Layout

- Public command docs: `docs/reference/`
- Maintainer-facing design docs: `docs/design/`
- Container workflow: `docs/developer/docker-development.md`
- Dependency source policy: `docs/developer/submodule-sources.md`
- Release workflow: [`RELEASING.md`](../../RELEASING.md)
