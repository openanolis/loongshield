# SEHarden Profile Format

Profiles are YAML documents consumed by `loongshield seharden`. They define levels, rules, probes, assertions, and optional reinforce actions.

## Top-Level Fields

- `id`: stable profile identifier, for example `agentos_baseline`.
- `title` or `policy`: human-readable name.
- `version`: profile version string.
- `levels`: ordered level list. Levels may use `inherits_from`.
- `default_level`: optional level ID used when the caller omits `--level`.
- `manual_review_required`: optional list of operator review items that stay outside automated host checks.
- `rules`: list of audit or reinforce rules.

## Rule Shape

Each rule typically includes:

- `id`: stable rule identifier.
- `desc`: operator-facing description.
- `level`: list of level IDs where the rule applies.
- `status`: usually `automated`.
- `probes`: one or more probe calls with `name`, `func`, and `params`.
- `assertion`: comparison tree using `all_of`, `any_of`, or `compare`.
- `reinforce`: optional list of actions with `action` and `params`.

## Manual Review Shape

Profiles may declare `manual_review_required` entries when a control depends on
deployment context or application semantics that SEHarden should not guess.

- `area`: short operator-facing area label, for example `openclaw_gateway`.
- `item`: concrete review prompt.
- `reason`: why the item stays outside automated host validation.
- `level`: optional list of level IDs that scope the item.

## Minimal Example

```yaml
id: sample_profile
title: Sample Profile
version: "0.1.0"
levels:
  - id: baseline
rules:
  - id: kernel.aslr
    desc: Ensure ASLR is enabled
    level: [baseline]
    status: automated
    probes:
      - name: aslr
        func: sysctl.get_live_value
        params: { key: kernel.randomize_va_space }
    assertion:
      actual: "%{probe.aslr}"
      key: value
      compare: equals
      expected: "2"
    reinforce:
      - action: sysctl.set_value
        params: { key: kernel.randomize_va_space, value: "2" }
```

## Resolution Rules

- Bare profile names resolve to `<rules_path>/<name>.yml`.
- Template references such as `%{probe.aslr}` read from earlier probe output.
- `--level` activates the selected level plus any inherited parent levels.
- If `--level` is omitted and `default_level` is defined, seharden uses that level; otherwise it runs all levels.
- When the active level matches `manual_review_required` entries, scan output includes a manual-review summary after automated results.

## Compatibility Notes

- The documented meaning of the fields on this page is part of the `loongshield seharden` public contract within a major release.
- Adding new optional fields or additive rule capabilities is compatible.
- Removing documented fields or changing their meaning incompatibly should be treated as a major-version change.

## Current Probe And Enforcer Namespaces

- Probes: `file`, `kmod`, `meta`, `mounts`, `network`, `packages`, `permissions`, `services`, `ssh`, `sysctl`, `users`
- Enforcers: `file`, `kmod`, `mounts`, `packages`, `permissions`, `services`, `sysctl`

Keep new profile docs caller-focused. Probe implementation details belong in design docs, not here.
