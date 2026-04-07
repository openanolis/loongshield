# rpm CLI

`loongshield rpm` verifies installed package files against a remote SPDX SBOM. The command is intended for operators and integrators; verification internals are documented separately.

The built-in default URL template targets the OpenAnolis / Alibaba Cloud Linux SBOM service. If your packages come from another repository, pass `--sbom-url` explicitly.

## Syntax

```sh
loongshield rpm --verify <package> [options]
```

## What It Does

1. Reads the installed package version, release, and architecture from the RPM database.
2. Builds an SBOM URL from the configured template.
3. Downloads the SPDX JSON SBOM.
4. Hashes installed files and compares them with SBOM checksums.

## Options

- `-v`, `--verify <package>`
- `--sbom-url <template>`
- `--verify-config`
- `--verbose`
- `--log-level <trace|debug|info|warn|error>`
- `-h`, `--help`

## URL Template Variables

- `{name}`
- `{version}`
- `{release}`
- `{arch}`
- `{name_first}`

Default template:

```text
https://anas.openanolis.cn/api/data/SBOM/RPMs/{name_first}/{name}-{version}-{release}.{arch}.rpm.spdx.json
```

For Fedora, local mirrors, private RPM repos, or any non-Anolis source, override the template with `--sbom-url`.

## Compatibility Notes

- Stable within a major release: documented flags, documented exit codes, and the documented URL template variable names.
- Human-readable verification output, mismatch wording, and verbose log formatting are not machine-readable APIs.
- The built-in SBOM URL template is a convenience default and may change between compatible releases. Automation that needs a fixed remote source should pass `--sbom-url` explicitly.
- If a release changes documented CLI behavior or template variables incompatibly, it should use a new major version.

## Exit Codes

- `0`: all verified files matched.
- `1`: package lookup, network, parse, or runtime error.
- `2`: checksum mismatches were found.

## Examples

```sh
loongshield rpm --verify bash
loongshield rpm --verify nginx --verify-config
loongshield rpm --verify curl --sbom-url "http://localhost:8080/{name}.json"
```

## Operational Notes

- This command requires an installed RPM package and network access to the SBOM source.
- The default template is ecosystem-specific; it is not a generic lookup service for every RPM distribution.
- Packages without published SBOMs will usually fail with a fetch error such as HTTP 404.
- Config files are skipped by default unless `--verify-config` is set.

## Related Docs

- Verification design: [../design/rpm-verification-design.md](../design/rpm-verification-design.md)
