# SEHarden Enforcer Guidelines

This page defines how SEHarden enforcers should be designed going forward.

The goal is to keep enforcers:

- small
- efficient
- clean
- easy to test
- consistent with the current probe-oriented design

It does not propose a new engine architecture. It assumes the current `engine + rule + reinforce` model stays in place and focuses only on enforcer implementation quality.

## Design Principles

### 1. One Enforcer, One Small State Change

An enforcer should do one narrow thing and do it well.

Good examples:

- `sysctl.set_value`
- `permissions.set_attributes`
- `file.append_line`
- `services.set_filestate`

Avoid enforcers that try to:

- inspect too much state
- encode benchmark policy
- make workflow decisions
- combine unrelated system changes

Keep business logic in profiles and the engine. Keep state writes in enforcers.

### 2. Prefer Target State Over Imperative Actions

An enforcer should express a desired state, not just fire a command.

Prefer:

- "make this file contain this key/value"
- "make this unit disabled"
- "make this sysctl equal 2"

Avoid imperative interfaces when a target-state interface is possible.

For example, `restart` is sometimes necessary, but `enabled = false` or `masked = true` is usually a cleaner long-term model than command-shaped APIs.

### 3. Enforcers Must Be Idempotent

Running the same enforcer twice should produce the same final state and should not create extra side effects.

Good idempotent behavior:

- do nothing if the target state is already correct
- avoid duplicate lines
- avoid duplicate config entries
- avoid repeated writes when no state change is needed

Idempotency matters because reinforce may be retried, re-run after partial failure, or executed repeatedly by operators and automation.

### 4. Validate Inputs Early And Strictly

Every enforcer should validate:

- required parameters
- types
- allowed value ranges
- path or unit-name safety
- shell-sensitive input when shell commands are used

Fail fast on invalid input. Do not silently coerce bad data into a different action.

### 5. Keep OS-Specific Mechanics In Helpers

Enforcers should stay short. Shared mechanics belong in helpers.

Examples of helper-worthy behavior:

- atomic file writes
- symlink refusal
- command execution wrappers
- safe path handling
- repeated file-edit patterns

If the same low-level logic appears in more than one enforcer, it should usually move into a shared utility.

### 6. Separate Read Logic From Write Logic

Probe-like inspection should stay out of enforcers unless the read is strictly needed to make the write idempotent or safe.

Use probes for:

- policy evaluation
- evidence collection
- rich reporting

Use enforcers for:

- minimal precondition checks
- narrow state changes
- simple verification needed for idempotency

### 7. Keep Return Semantics Simple

For the current design, keep the existing contract:

- success: `true`
- failure: `nil, err`

That is enough for now. The important part is to make the error message specific and useful.

Good errors should tell the caller:

- what action failed
- what target failed
- whether the issue was validation, execution, or persistence

### 8. Make Dependencies Injectable For Tests

Every enforcer should keep external dependencies behind a small injectable table, typically via `_test_set_dependencies`.

That includes:

- file I/O
- process execution
- system libraries
- path metadata

The ideal enforcer can be tested without requiring the real host state.

### 9. Prefer Declarative File Mutations

When editing files, the enforcer should describe the intended file state, not depend on fragile shell text rewriting.

Prefer:

- replace-or-append one key
- append one exact line if missing
- remove lines matching one rule

Avoid large opaque shell pipelines for file edits when a small Lua implementation is practical.

### 10. Be Explicit About Scope And Limits

If an enforcer cannot guarantee a stronger property, say so in code comments or documentation.

Examples:

- persists config but does not reload service
- applies live state but cannot guarantee reboot-time persistence
- updates one config file but does not deduplicate equivalent settings elsewhere

Clear limits are better than pretending an action is more complete than it really is.

## Review Rubric

Use these questions when adding or reviewing an enforcer:

1. Is the action narrow and single-purpose?
2. Does it express target state instead of workflow?
3. Is it idempotent?
4. Does it validate all inputs strictly?
5. Does it avoid duplicated low-level logic?
6. Is it easy to test with injected dependencies?
7. Are error messages specific?
8. Are its limits explicit?
