---
applyTo: "docs/**,dist/**,.github/workflows/**,Makefile,VERSION,CHANGELOG.md,RELEASING.md,CONTRIBUTING.md,.github/PULL_REQUEST_TEMPLATE.md"
---

# Docs, Packaging, And CI Review Instructions

These paths define user-facing contracts, packaging behavior, and contributor workflows.

- CLI and profile documentation under `docs/reference/` must match actual behavior and examples.
- Version, changelog, release checklist, spec files, and RPM source-bundle logic must stay consistent.
- CI changes should preserve coverage for build, format, RPM, and commit-title checks unless the PR clearly justifies a change.
- Workflows should use minimal permissions and avoid leaking secrets or widening write access.
- Packaging changes should be tested with `make rpm` or `make rpm-in-docker` when practical.
- If a PR changes documented CLI behavior, profile semantics, machine-readable output, or packaging metadata, expect implementation, docs, and tests to move together.
