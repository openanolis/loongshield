# seharden CLI

`seharden` audits a host against a YAML profile and can optionally apply reinforce actions for failed rules.

The default bundled profile is `cis_alinux_3`, which targets the CIS Alibaba Cloud Linux 3 Benchmark v2.0.0 and similar OpenAnolis-style hosts. On other RPM-based systems, pick an explicit profile with `--config`.

## Syntax

```sh
loongshield seharden [--scan|--reinforce] [options]
```

## Inputs

- `--config <name|path>`: profile name or explicit YAML path. If a bare name is used, Loongshield resolves it under `/etc/loongshield/seharden`.
- `--level <level>`: run only the selected level and its inherited parents. If omitted, seharden uses the profile default level when defined; otherwise it runs all levels.
- `LOONGSHIELD_SEHARDEN_RULES_PATH`: overrides the default profile search directory.
- `LOG_LEVEL`: optional default log level unless `--log-level` is passed.

Bundled profile examples in this repository live under `profiles/seharden/`.

## Modes

- `--scan`: audit only. This is the default.
- `--reinforce`: apply configured reinforce actions for failed rules.
- `--dry-run`: show reinforce actions without changing the system. Only meaningful with `--reinforce`.

`--reinforce` is non-transactional. Partial changes are possible if a later rule fails.

## Options

- `--config <ruleset>`
- `--level <level>`
- `--dry-run`
- `--format <text|json>`: output format. `text` is the default.
- `--verbose`: print rule-by-rule results with compact evidence intended for operators.
- `--log-level <trace|debug|info|warn|error>`
- `-h`, `--help`

## Compatibility Notes

- Stable within a major release: documented mode flags, documented option meanings, documented exit codes, and the documented meaning of SEHarden profile fields consumed by this command.
- `--format json` is the machine-readable output contract for automation.
- `--verbose` output is for operators, not a machine-readable API. Exact wording, colors, ordering, and evidence formatting may change between compatible releases.
- `--log-level debug` exposes developer-oriented trace output and should be treated as less stable than the normal operator-facing CLI contract.
- If automation depends on a specific bundled profile, pass `--config` explicitly instead of relying on the default profile choice.
- If a release changes documented behavior incompatibly, it should use a new major version.

## Output Modes

- Default output keeps the standard logger format and final summary.
- `--verbose` switches to a plain-text, human-friendly rule report with focused probe evidence.
- `--format json` prints one JSON object to stdout. This is the stable v1 automation contract.
- Scan output appends a manual-review summary when the selected profile/level declares `manual_review_required` items.
- `--log-level debug` keeps the underlying developer-oriented execution trace when you need full probe and engine diagnostics.

### JSON Contract v1

Automation should call `loongshield seharden --format json` and parse only the JSON object. Do not parse the default text or `--verbose` output.

Stable top-level fields:

- `schema_version`: integer. Current value: `1`.
- `format`: string. Current value: `json`.
- `tool`: string. Current value: `loongshield`.
- `command`: string. Current value: `seharden`.
- `status`: `passed` when `exit_code` is `0`, otherwise `failed`.
- `mode`: `scan` or `reinforce`.
- `profile`: resolved profile id when available, otherwise the requested config value.
- `level`: resolved profile level, or `all`.
- `dry_run`: boolean.
- `request`: object with `mode`, `config`, `profile`, `level`, `requested_level`, and `dry_run`.
- `rules`: rule result list. Each item has `id`, `desc`, `status`, and optional `reason`.
- `rule_count`: number of rule result items.
- `summary`: object with `passed`, `fixed`, `failed`, `manual`, `dry_run_pending`, and `total`.
- `manual_review`: manual-review entries for scan mode.
- `manual_review_count`: number of manual-review entries.
- `available_levels`: level ids when reporting invalid level selection.
- `exit_code`: process exit code.
- `error`: error message for CLI/profile/schema failures.

Nullable fields are emitted as JSON `null`, not omitted. `rules`, `manual_review`, and `available_levels` are always JSON arrays when present as collections, including empty arrays. Consumers should still use `rule_count`, `manual_review_count`, and `summary` for counts.

## Exit Codes

- `0`: scan passed, or reinforce completed with no remaining failures.
- `1`: CLI error, profile load error, scan failure, or dry-run pending changes.

## Examples

```sh
loongshield seharden
loongshield seharden --config agentos_baseline
loongshield seharden --config agentos_baseline --format json
loongshield seharden --config agentos_baseline --verbose
loongshield seharden --config agentos_baseline --log-level debug
loongshield seharden --config cis_alinux_3 --level l1_server
loongshield seharden --reinforce --config agentos_baseline --dry-run
loongshield seharden --reinforce --config /etc/loongshield/seharden/dengbao_3.yml
```

## External Cross-Verification

Use `--format json` as the SEHarden side of any independent verification workflow. For OpenSCAP, run the matching external profile separately, save the XCCDF or ARF result, then compare the two outputs with an explicit rule mapping:

```sh
loongshield seharden --config cis_alinux_3 --level l1_server --format json > seharden.json
oscap xccdf eval --profile <profile-id> --results oscap-results.xml <xccdf-content.xml>
python3 tools/seharden/cross_verify.py \
  --seharden-json seharden.json \
  --external-xccdf oscap-results.xml \
  --mapping cis-alinux3-oscap-map.json
```

For reinforce validation, run the same comparison after `loongshield seharden --reinforce ...` and a fresh external scan. The verifier treats SEHarden `PASS` and `FIXED` as pass, hard failures and `DRY-RUN` as fail, and manual checks as non-automated. Use a real reinforce run plus a fresh external scan when checking whether remediation changed the host; comparing SEHarden dry-run output to a live OpenSCAP scan will usually report mismatches because dry-run intentionally leaves the host unchanged.

The mapping file must be a JSON object from SEHarden rule ID to the external XCCDF rule ID:

```json
{
  "1.1.1.1": "xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled"
}
```

Do not rely on automatic ID matching between CIS section IDs and OpenSCAP rule IDs. The two projects use different identifiers, and an explicit mapping prevents false matches. Add `--require-all-mapped` when unmapped SEHarden rules should fail the verification, and `--format json` when another tool needs the comparison report. If an external XCCDF or ARF file contains multiple `TestResult` elements, pass `--test-result-id <id>` to select the run to compare. Mismatches are reported only when both sides have a definitive pass/fail result; OpenSCAP results such as `notchecked`, `notapplicable`, or `notselected` are reported as inconclusive.

## Related Docs

- AgentOS baseline Skill workflow: [../skill/agent-sec-seharden.md](../skill/agent-sec-seharden.md)
- AgentOS baseline design note: [../design/agentos-seharden-design.md](../design/agentos-seharden-design.md)
- Profile format: [seharden-profile-format.md](./seharden-profile-format.md)
- Runtime internals: [../design/runtime-architecture.md](../design/runtime-architecture.md)
