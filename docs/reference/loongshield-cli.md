# loongshield CLI

`loongshield` is the top-level command entry point for operator-facing features. The public contract is the CLI, not the internal Lua module layout.

Current bundled defaults are centered on OpenAnolis / Alibaba Cloud Linux style RPM hosts. On other RPM-based systems, pass an explicit SEHarden profile or SBOM URL instead of assuming the built-in defaults fit your environment.

## Syntax

```sh
loongshield <subcommand> [options]
```

Local builds produce the binary at `build/src/daemon/loongshield`. Installed systems should expose it as `loongshield`.

## Compatibility Contract

- Stable within a major release: documented subcommand names, documented option meanings, documented exit codes, and documented configuration inputs consumed through the CLI.
- Not stable: internal Lua module paths, embedded runtime layout, build internals, and human-readable log or debug wording.
- If a release breaks documented CLI behavior incompatibly, it should use a new major version.

## Subcommands

- `version`: print the build version and commit.
- `seharden`: audit or reinforce a security profile.
- `rpm`: verify an installed RPM against a remote SBOM.

Run subcommand help directly:

```sh
loongshield seharden --help
loongshield rpm --help
```

## Typical Usage Examples

```sh
loongshield version
loongshield seharden --config agentos_baseline
loongshield rpm --verify bash
```

## Documentation Map

- SEHarden usage: [seharden-cli.md](./seharden-cli.md)
- SEHarden profile format: [seharden-profile-format.md](./seharden-profile-format.md)
- RPM verification usage: [rpm-cli.md](./rpm-cli.md)
