# Why AgentOS Uses This SEHarden Design

This page explains why `profiles/seharden/agentos_baseline.yml` looks the way it does.

It is not a rule reference. It is a short design note for people who want to understand the thinking behind the baseline.

## The Runtime Problem We Are Solving

An AgentOS runtime is not a normal desktop and not a general-purpose multi-user server.

It runs agent workloads that may handle untrusted prompts, tools, files, and network input. In that kind of environment, a few risks matter more than others:

- turning the host into a network pivot
- exposing secrets or sensitive system state
- leaving extra local services available for abuse
- making it too easy for one compromised process to inspect or influence others

The baseline is shaped around those risks.

## Why The Baseline Is Intentionally Small

`agentos_baseline` is meant to be a strong default, not a giant compliance program.

That is why the profile stays focused on a small set of controls that have clear value for agent workloads:

- kernel settings that reduce information leaks and unsafe tracing
- network settings that stop router-like behavior
- `/dev/shm` mount flags that reduce easy code-execution tricks
- permissions on core account and secret files
- a minimal service footprint

A smaller baseline is easier to read, easier to explain, and safer to reinforce.

It also keeps the signal clean. When an operator sees a failure, it should usually mean something worth fixing for this runtime, not just a generic benchmark item that happens to exist on Linux.

## Why We Use A Profile-Driven Design

The hardening policy lives in YAML, while the runtime engine stays generic.

That split matters because the policy for agent workloads will keep changing. Threats change. Packaging changes. Runtime expectations change. We do not want to rewrite the engine every time the baseline moves a little.

By keeping the baseline in `agentos_baseline.yml`, we can adjust the policy without turning every rule update into a runtime redesign.

## Why Scan And Reinforce Are Separate

Reading system state and changing system state are different actions. They should not be mixed together by default.

That is why SEHarden separates:

- `scan`: inspect only
- `reinforce`: apply changes
- `dry-run`: preview changes first

This makes the tool easier to trust. Operators can see what is wrong before deciding whether to change a running host.

For an AgentOS runtime, that matters. These systems often run automation, so safe defaults and explicit change steps are more important than trying to be clever.

## Why The Rules Stay Close To Real Host State

The baseline mostly checks direct host facts:

- sysctl values
- mount options
- file ownership and permissions
- package presence
- service state

This keeps the results understandable. A failure is tied to a real system setting, not to a hidden score or a long chain of assumptions.

That is useful for both people and automation. Humans can read the result and know what changed. Tools can reinforce the same rule without guessing what the system meant.

## Why The Service Rules Are Narrow

The service section is intentionally small.

For AgentOS, the goal is not to ban every optional service on a Linux host. The goal is to remove obvious services that do not fit a lean agent runtime, especially services that advertise the host or open extra local attack surface.

That is why `agentos_baseline` focuses on a few clear cases such as `avahi-daemon.service` and `cups.service`.

This keeps the baseline practical across more environments. A short list of high-value service rules is usually better than a large blacklist that creates noise and distro-specific surprises.

## What This Design Optimizes For

In simple terms, this design optimizes for three things:

- clear operator signal
- low-friction hardening
- controls that match the actual risk shape of an agent runtime

That is the reason the profile is compact, profile-driven, and split into scan and reinforce behavior.

It is a practical baseline for real hosts, not a checklist written for its own sake.
