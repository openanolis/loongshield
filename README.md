# Loongshield

Loongshield is host security tooling for RPM-based Linux systems. It currently combines
profile-driven auditing, optional hardening actions, and RPM package file verification in a native C/Lua runtime.

## Usage Examples

```sh
loongshield seharden --scan --config dengbao_3 --verbose
loongshield rpm --verify nginx --config https://example.com/sbom.json
```

## Quick Start

Build requirements and contributor workflow live in
[docs/developer/build-and-test.md](docs/developer/build-and-test.md).

For a fresh checkout on a compatible RPM-based host:

```sh
make bootstrap
make test
```

Build outputs are written under `build/`, including:

```text
build/src/daemon/loongshield
build/src/daemon/loonjit
```

If your host is not suitable for a native build, use the container workflow in
[docs/developer/docker-development.md](docs/developer/docker-development.md).

## Common Commands

```sh
make bootstrap
make test
make install
make rpm
make rpm-in-docker
```

## Environment Notes

- Development, testing, and packaging workflows assume an RPM-based Linux environment.
- `loongshield seharden` defaults to the bundled `cis_alinux_3` profile.
- `loongshield rpm` defaults to the OpenAnolis SBOM service.
- On other RPM-based distributions, expect to pass an explicit `--config` or `--sbom-url`.

## Project Scope

- Currently focused on host hardening and verification on RPM-based Linux with systemd.
- The optional kernel module under `src/kmod/` is not required for normal userspace workflows.
- The project is released under the [MIT License](LICENSE).

## Versioning And Compatibility

- The stable public surface for `1.x` is the documented CLI.
- That contract includes documented subcommands, option meanings, exit codes, and documented SEHarden profile semantics consumed by the CLI.
- Internal Lua module names, embedded runtime layout, generated assets, and developer-oriented debug output are not stable external APIs.
- Human-readable operator output may be refined between compatible releases. Automation should prefer exit codes, explicit flags, and explicit profile or SBOM settings over parsing presentation text.
- If a release removes or redefines documented CLI behavior incompatibly, it should use a new major version instead of dropping back to `0.x`.

## Documentation

- Overview: [docs/README.md](docs/README.md)
- Top-level CLI: [docs/reference/loongshield-cli.md](docs/reference/loongshield-cli.md)
- SEHarden usage: [docs/reference/seharden-cli.md](docs/reference/seharden-cli.md)
- SEHarden profile format: [docs/reference/seharden-profile-format.md](docs/reference/seharden-profile-format.md)
- RPM verification usage: [docs/reference/rpm-cli.md](docs/reference/rpm-cli.md)
- Build and test: [docs/developer/build-and-test.md](docs/developer/build-and-test.md)
- Docker workflow: [docs/developer/docker-development.md](docs/developer/docker-development.md)
- Submodule source policy: [docs/developer/submodule-sources.md](docs/developer/submodule-sources.md)
- Architecture notes: [docs/design/runtime-architecture.md](docs/design/runtime-architecture.md), [docs/design/clean-architecture.md](docs/design/clean-architecture.md)

## Community

- Release history: [CHANGELOG.md](CHANGELOG.md)
- Release checklist: [RELEASING.md](RELEASING.md)
