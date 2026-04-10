# Releasing Loongshield

This checklist is for maintainers cutting a public release.

## Version Sources Of Truth

Keep these in sync for every release:

- `VERSION`
- `CHANGELOG.md`
- `dist/loongshield.spec` (`Version:` and `%changelog`)
- Git tag `vX.Y.Z`

## Pre-Release Validation

Start from a clean branch with submodules initialized:

```sh
git submodule update --init --recursive
make test
make rpm-in-docker
```

Run additional validation when relevant:

- `make kmod` if the kernel module changed
- `make test-integration` if the change affects live host behavior
- `git diff --check` before tagging
- Re-check retained fork-backed submodules in `docs/developer/submodule-sources.md` when updating vendored dependencies

## Choose The Release Type

- Patch release (`X.Y.Z` to `X.Y.Z+1`): compatibility-preserving bug fixes, docs, packaging fixes, and behavior corrections that do not break the documented CLI contract.
- Minor release (`X.Y.Z` to `X.Y+1.0`): additive CLI options, new bundled profiles, new additive profile capabilities, or other backward-compatible features.
- Major release (`X.Y.Z` to `X+1.0.0`): incompatible changes to documented subcommands, option meanings, exit codes, URL template variables, or documented SEHarden profile semantics.
- Do not drop back to `0.x`. The release line already treats the documented CLI as the public contract.
- Human-readable output wording, verbose rendering, and internal implementation refactors do not require a major release on their own unless the documented CLI contract changes.

## Prepare The Release

1. Choose the release version using the rules above.
2. Update `VERSION`.
3. Move the relevant entries from the `Unreleased` section of `CHANGELOG.md` into a new dated release section.
4. Update `dist/loongshield.spec`:
   - Set `Version:` to the new release
   - Add a matching `%changelog` entry
   - If any top-level submodule pin changed, update the vendored commit list in `dist/rpm-vendor-sources.txt` and the matching `SourceN` block in `dist/loongshield.spec`
5. Commit the release prep with a subject such as `release: cut vX.Y.Z`.

## Tag And Publish

Create an annotated tag and push both the branch and tag:

```sh
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

Then publish the hosted release entry using the same version number and changelog summary.

If you distribute RPM artifacts, upload the packages built under:

```text
build/rpmbuild-docker/RPMS/
```

## Post-Release Follow-Up

- Re-open `CHANGELOG.md` with a fresh `Unreleased` section.
- Verify README and reference docs still describe the released behavior.
- If the release includes a security fix, publish a suitable release note or advisory as described in `SECURITY.md`.
