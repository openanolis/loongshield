# Lua-LSM Native Support

Lua-LSM is a kernel-provided built-in Linux Security Module. Loongshield treats
it as a runtime capability exposed through securityfs, not as another
out-of-tree kernel module under `src/kmod/`.

## Boundary

Loongshield owns:

- readiness checks for the running kernel
- policy validation before explicit load
- securityfs read/write orchestration
- operator CLI and packaging of example policies
- fake-securityfs tests for normal CI

The kernel owns:

- `CONFIG_LUA`
- `CONFIG_SECURITY_LUA_LSM`
- LSM hook registration
- `/sys/kernel/security/lua/*`
- policy execution inside the kernel Lua VM

## Runtime ABI

The userspace manager talks to these securityfs files:

- `version`
- `register`
- `unregister`
- `modules`
- `stats`
- `lsm_funcs`

Only `register` and `unregister` are written. The CLI checks effective
`CAP_MAC_ADMIN` before writes so operators get a clear userspace error before
the kernel rejects the write.

## Package Layout

Bundled example policies are installed under:

```text
/etc/loongshield/lua-lsm/policies.d/
```

The example manifest is informational and does not trigger autoload:

```text
profiles/lua-lsm/manifest.yml
```

## Safety Gate

The feature remains experimental because the inspected Lua-LSM source tree has
documented high-risk audit findings, including memory lifetime, refcount, RCU,
and hook contract issues. Loongshield therefore does not auto-load policies and
marks the CLI surface as experimental in status/help/docs.

Before production use, either fix the kernel audit blockers or enforce a
conservative policy allowlist in Loongshield that only permits audited hook
wrappers.

## Test Strategy

Normal CI uses a fake securityfs root through
`LOONGSHIELD_LUA_LSM_SECURITYFS_ROOT` or direct module options. That covers
status, doctor, list, load, unload, stats, and hooks behavior without requiring
privileged kernel state.

Privileged end-to-end coverage should run in a VM with:

```text
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_LUA=y
CONFIG_SECURITY_LUA_LSM=y
CONFIG_LSM=...,lua,...
```

The VM test should load a narrow policy, prove the target hook behavior, unload
the policy, and verify the behavior is gone.
