# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Breaking
- None yet.

### Added
- None yet.

### Changed
- None yet.

### Fixed
- None yet.

## [1.1.3] - 2026-04-08

### Added
- Public project governance and contribution documents: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `SUPPORT.md`, and `RELEASING.md`.
- Repository contribution scaffolding: `.editorconfig`, issue templates, and a pull request template.

### Changed
- Document `1.x` compatibility rules around the CLI contract, documented profile semantics, and major-version triggers for breaking changes.
- Reworked the top-level README and documentation index to better separate operator docs, contributor docs, and maintainer design notes.
- CI now runs `make test-quick` in the distro build matrix, not just compilation.
- RPM packaging metadata was cleaned up for public distribution by removing private repository references and corporate email addresses.
- `seharden` no longer exposes a separate `--debug` shortcut; use `--log-level debug` when developer trace output is needed.
- `seharden` now centralizes executable rule-schema validation and shares output, loader, and config-parsing helpers across engine, probes, and enforcers.

### Fixed
- Repository community/process links now resolve to checked-in governance documents.
- `seharden` user probes now parse `/etc/shadow` entries correctly, including empty fields.
- Service enforcers now fail on non-zero `systemctl` exit status instead of treating stderr text alone as the source of truth.
- RPM file list parsing no longer breaks on paths containing spaces.
- Persistent hardening config writers now use temp-file plus rename and refuse symlink overwrite for safer remediation.
- `seharden` now rejects malformed active rules more consistently while allowing inactive rules with unknown comparators to remain loadable for other profile levels.
- Local builds now fail early on unsupported host distributions instead of failing later in the pipeline.
- Build and CI packaging flows now align with supported EL9 and arm64 environments, use public `libsystemd`, and avoid the unused `libnm` dependency.

## [1.1.2] - 2026-03-26

### Changed
- `seharden --verbose` now renders a compact operator-friendly report, while full developer execution trace output remains available through log-level controls.
- `make help` has been reorganized into clearer sections and now documents `test-quick` alongside the other test targets.

### Fixed
- `seharden` scan diagnostics now surface more focused probe evidence and avoid repeated noisy log lines in verbose mode.
- Verbose-output regression tests now disable ANSI color during output assertions so `make test-quick` behaves consistently across terminal environments.

## [1.1.1] - 2026-03-13

### Added
- **AgentOS security baseline profile** (`profiles/seharden/agentos_baseline.yml`): 23-rule minimal profile for AI agent workloads covering kernel hardening, network isolation, `/dev/shm` mount options, secret file permissions, and service footprint.

### Fixed
- `mounts.remount`: missing fstab entry now logs a warning and returns success (live remount proceeds) instead of `ENFORCE-ERROR`. Fixes `/dev/shm` enforcement on systemd hosts where the mount is not managed via fstab.
- `agentos_baseline`: absent service units now detected via `UnitFileState == "not-found"` instead of `is_falsy`, matching the actual value returned by `services.get_unit_properties`.
- `agentos_baseline`: filesystem module rules now assert the module is not currently loaded (`kmod.is_loaded`) in addition to blacklist and install-command checks.

## [1.1.0] - 2026-03-13

### Added
- **SEHarden reinforce mode** (`loongshield seharden --reinforce`): declarative, probe-driven remediation symmetric to the existing audit system.
- **Enforcer modules**: `kmod` (unload, blacklist, set\_install\_command), `sysctl` (set\_value with live + persistent write), `services` (set\_filestate, set\_active\_state), `permissions` (set\_attributes), `file` (append\_line, set\_key\_value, remove\_line\_matching), `mounts` (remount + fstab update), `packages` (install, remove).
- **`enforcerloader`** module: mirrors `probeloader` with module caching and `module.function` path resolution.
- **`--dry-run` flag**: validates enforcer availability and logs what would be applied without making changes; exits non-zero when fixes are pending.
- **Auto-verify after enforcement**: re-audits each rule after applying reinforce steps; reports `FIXED` or `FAILED-TO-FIX`.
- **Probe cache invalidation** (`probeloader.reset_caches`): clears stale cached state before re-audit so re-reads reflect actual system changes.
- **Reinforce sections** in CIS ALinux 3 profile for kmod rules (cramfs, freevxfs, jffs2) and ASLR sysctl rule.
- Unit tests for all seven enforcer modules and all reinforce engine result categories (FIXED, FAILED-TO-FIX, MANUAL, DRY-RUN, ERROR).
- Integration test for engine probe template substitution.

### Changed
- `engine.run` now accepts an `opts` table (`{ dry_run = bool }`).
- `run_audit` returns `probed_data` as a third value for use by `run_enforce`.
- Result counters split into `passed`, `fixed`, `manual`, `dry_run_pending`, `hard_failures`.
- `MANUAL` (no reinforce steps defined) is informational only and does not count as a hard failure.
- Non-transactional warning logged at the start of every live reinforce run.

### Fixed
- `validate_reinforce_steps` enforces `module.function` format for action names before attempting to load the enforcer.
- `mounts.remount`: skip fstab write when all requested options are already present (true idempotency).
- `kmod` enforcer: use `error("found", 0)` in `line_exists_in_modprobe_d` to prevent Lua prepending source location to the sentinel string, breaking the pcall match.

## [1.0.0] - 2025-09-16

### Added
- Initial stable release of the SEHarden engine.
