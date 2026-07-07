---
applyTo: "src/daemon/modules/seharden/**/*.lua,profiles/seharden/**/*.yml,docs/reference/seharden*.md,docs/design/seharden*.md,tests/**/seharden*.lua"
---

# SEHarden Review Instructions

SEHarden changes are security-sensitive because they can inspect or modify host configuration.

- Enforcers should make one narrow state change. Keep policy and workflow decisions in profiles and the engine.
- Prefer target-state APIs over command-shaped imperative APIs.
- Enforcers must be idempotent. Re-running reinforce must not duplicate config, repeatedly rewrite unchanged files, or create extra side effects.
- Validate required parameters, types, allowed values, path safety, unit-name safety, and shell-sensitive input before doing host writes.
- Avoid shell pipelines for file mutation when a small Lua implementation is practical.
- Keep external dependencies injectable, usually through `_test_set_dependencies`, so tests do not require real host state.
- Preserve the enforcer return contract: success is `true`; failure is `nil, err` with a specific error.
- Be explicit when a function updates config but does not reload a service, applies live state but not persistent state, or only edits one config file among several effective sources.
- Profile changes must keep `params` shaped exactly as the rule executor expects and should include tests when they add or alter reinforce behavior.
- Probe logic should collect evidence and policy state. Enforcers should only read enough state to make writes safe and idempotent.
