# Architecture Rationale

This page explains why Loongshield is built the way it is. It is not a theory page. The point is to help a reader look at the codebase and understand the choices behind it.

For build steps and runtime startup flow, see `docs/design/runtime-architecture.md`.

## The Problem Loongshield Is Solving

Loongshield does two jobs:

- `loongshield seharden` checks a host against security baselines and can optionally apply fixes.
- `loongshield rpm` verifies installed RPM files against a remote SPDX SBOM.

Both jobs need real Linux integration. They need to talk to things like RPM, systemd, mount tables, `/proc/sys`, file ownership, and sometimes kernel-module state. At the same time, the security rules and operational policy change much faster than the runtime itself.

That is the main reason the project is split the way it is: keep the Linux-facing runtime small, and keep the policy layer easier to change.

## Why The Runtime Is Small C And Most Logic Is Lua

The C entrypoint in `src/daemon/main.c` is intentionally thin. It starts Lua, opens the built-in native libraries from `src/daemon/lualibs.c`, and hands control to the embedded Lua entrypoint.

This gives Loongshield a clear split:

- C is used where direct system libraries and low-level bindings matter.
- Lua is used where the code is mostly orchestration, data handling, rule evaluation, and CLI behavior.

That split makes sense for this project because most of the complexity is not in bootstrapping a process. The complexity is in expressing security checks and remediation flows in a way that can keep evolving.

If every benchmark rule lived in C, adding or changing policy would be slower, harder to review, and more tightly coupled to the runtime. By moving most of the behavior into Lua, Loongshield keeps the platform-facing layer narrow and the policy layer flexible.

## Why The Lua Code Is Embedded

Loongshield does not depend on loose Lua scripts sitting next to the binary at runtime. During the build, `src/daemon/build.lua` packages the Lua modules into generated headers, and `src/daemon/ramfs.c` boots from that embedded payload.

This has a few practical benefits:

- the shipped runtime is self-contained
- the daemon does not depend on host Lua search paths
- the code that runs is the code that was built and packaged together
- versioned binaries and embedded modules stay in sync

For a security tool, that is a sensible tradeoff. Predictable runtime layout matters more here than a very dynamic plugin installation story.

## Why SEHarden Is Profile-Driven

The SEHarden engine is built around YAML profiles in `profiles/seharden/*.yml`, loaded by `src/daemon/modules/seharden/profile.lua` and executed by `src/daemon/modules/seharden/engine.lua`.

This is one of the most important design choices in the project.

The baseline itself is treated as data, not hardcoded program logic. That lets Loongshield support different audiences without rewriting the engine:

- `cis_alinux_3.yml` for CIS-style operating system checks
- `dengbao_3.yml` for another benchmark set
- `agentos_baseline.yml` for AI agent host hardening

The `levels` and `inherits_from` fields show the same idea. One profile can express several compliance levels without duplicating the whole rule set.

This design makes sense because the benchmark content changes faster than the execution model. The engine stays mostly the same while profiles carry the policy.

## Why A Rule Is Split Into Probe, Assertion, And Reinforce

A SEHarden rule is not a single opaque function. It is usually split into:

- one or more probes to collect facts
- an assertion tree to decide pass or fail
- optional reinforce steps to apply a fix

This is not accidental. It gives Loongshield a few useful properties:

- scan mode can check the system without changing it
- reinforce mode can reuse the same rule definition
- `--dry-run` can preview actions safely
- the engine can re-audit after a fix and report whether the rule was actually fixed

The tests make this intent clear. The reinforce flow distinguishes between `MANUAL`, `FIXED`, `FAILED-TO-FIX`, and dry-run results, instead of treating remediation as a blind command runner.

That matters for a hardening tool. Auditing and changing a system are not the same level of risk, so the code keeps them separate on purpose.

## Why There Are Many Small Probe And Enforcer Modules

Loongshield could have been written as a pile of large benchmark-specific functions. Instead, it uses many small modules under:

- `src/daemon/modules/seharden/probes/`
- `src/daemon/modules/seharden/enforcers/`

That shape fits the problem better.

A benchmark rule might need data from very different places:

- `/proc/sys` for sysctl values
- libkmod for kernel module state
- libmount for mount information
- D-Bus or `systemctl` for service state
- RPM queries for installed packages
- plain files like `/etc/ssh/sshd_config` or `/etc/passwd`

Small modules keep each integration narrow. The profile then composes those pieces into rules.

This is why the engine can stay generic. It does not need a built-in function for every benchmark item. It only needs a way to run named probes, evaluate their results, and call named reinforce actions.

The interpolation model, such as `%{probe.<name>}`, and helper probes like `meta.map` show the same idea: collect facts first, then compose them into higher-level checks.

## Why The Code Uses Native Bindings And Shell Fallbacks

Loongshield is pragmatic about system integration.

Where Linux already exposes a good library interface, the project uses native bindings:

- `lua_kmod.c` for libkmod
- `lua_systemd.c` for systemd and D-Bus interactions
- `lua_mount.c` for mount state
- `lua_rpm.c` and other bindings for system-facing functionality

That avoids fragile text parsing when a structured API already exists.

At the same time, the project does not pretend every useful system query has a clean library interface everywhere. Some modules still use shell commands or plain file reads:

- `services.lua` prefers D-Bus for unit-file state but falls back to `systemctl show`
- package queries use `rpm` CLI calls in several places
- sysctl checks read from `/proc/sys`
- file and SSH probes read configuration directly or shell out when needed

This is a deliberate tradeoff. The design goal is reliable host inspection, not ideological purity. When a shell fallback is the practical answer, Loongshield uses it, usually with input sanitization and tests around the edge cases.

## Why RPM Verification Is A Separate Command

`loongshield rpm` is not just another SEHarden rule set. It solves a different problem.

SEHarden is about host posture and remediation. RPM verification is about package-file integrity against a remote SBOM source.

That is why the RPM path has its own modules:

- `src/daemon/modules/rpm/cli.lua`
- `src/daemon/modules/rpm/verify.lua`
- `src/daemon/modules/rpm/sbom.lua`
- `src/daemon/modules/rpm/checksum.lua`

It also has a different runtime shape. The SBOM fetch path uses `uvcurl` and `luv`, and the CLI explicitly drives the event loop with `uv.run()`. That makes sense here because remote fetch is central to the feature, while SEHarden mostly reads local system state.

Keeping the RPM feature separate prevents the project from forcing two very different workflows into one engine.

## Why The Kernel Module Is Optional

The `src/kmod/` tree is intentionally separate from the main daemon build path.

Most of Loongshield's value is in userspace:

- reading system state
- evaluating policy
- writing controlled remediations
- verifying installed packages

The optional `sysmon` kernel module sits at the edge for cases where kernel-level capability is useful. It is not the center of the architecture.

That is a good design choice for a security tool that still needs to be buildable, deployable, and operable on ordinary hosts. Kernel code is higher cost and higher risk, so Loongshield keeps it optional instead of making it a hard dependency for everything.

## Why Testing Is Layered This Way

The test layout matches the architecture:

- `tests/unit/` checks small pieces of logic
- `tests/integration/` checks module interaction and filesystem-style behavior
- `tests/e2e/` is reserved for full flows, even though some revisions may not yet ship checked-in e2e suites

More importantly, many probes and enforcers expose `_test_set_dependencies`. That is a strong signal about the intended design.

The project wants to test policy and orchestration without depending on a real host state for every case. That is why service probes, kmod handling, file writers, sysctl writers, and similar modules can be stubbed in tests.

For this codebase, that is the right compromise. Security logic still needs realistic integration tests, but the engine and adapters must also be testable in isolation.

## The Big Picture

If you reduce the whole codebase to one idea, it is this:

Loongshield keeps policy, rule composition, and operator flow in Lua and YAML, while pushing OS-specific power to a relatively small runtime edge made of native bindings, shell adapters, and an optional kernel module.

That gives the project a few things at once:

- enough low-level access to manage a real Linux host
- enough flexibility to evolve benchmarks and hardening rules quickly
- enough structure to keep scan, reinforce, and verification behaviors understandable

## Current Tradeoffs

The code is not trying to be academically pure, and that is visible in a few places:

- some orchestration modules still know too much about lookup and runtime details
- some RPM and service flows still mix business logic with transport or shell behavior
- global native-library registration keeps the runtime simple, but it also makes dependencies less explicit than they could be

Those are real tradeoffs, but they do not change the overall design story.

The project is built this way because Loongshield needs to be both a real Linux systems tool and a fast-moving security policy engine. The current architecture reflects that balance.
