# Lua-LSM CLI

`loongshield lua-lsm` manages Lua-LSM policies through the kernel securityfs
ABI at `/sys/kernel/security/lua`.

Lua-LSM support is experimental. Loongshield does not auto-load policies during
install or startup. Loading a policy is always an explicit operator action.

## Syntax

```sh
loongshield lua-lsm <command> [options]
```

## Commands

- `status`: show whether the Lua-LSM securityfs ABI is present.
- `doctor`: run readiness checks for securityfs, active LSM order, and kernel config.
- `list`: show loaded Lua-LSM modules.
- `load <policy.lua>`: validate policy metadata and write the policy to `register`.
- `unload <name>`: write the module name to `unregister`.
- `hooks`: print `lsm_funcs` when `CONFIG_SECURITY_LUA_LSM_STATS=y`.
- `stats`: print VM/cache stats when `CONFIG_SECURITY_LUA_LSM_STATS=y`.

## Options

- `--root <path>`: override the Lua-LSM securityfs root.
- `--config <path>`: override the kernel config path used by `doctor`.
- `--no-validate`: skip userspace metadata validation before `load`.
- `--log-level <level>`: set log level.
- `-h`, `--help`: show command help.

## Environment

- `LOONGSHIELD_LUA_LSM_SECURITYFS_ROOT`: defaults to `/sys/kernel/security/lua`.
- `LOONGSHIELD_LUA_LSM_SECURITYFS_MOUNT`: defaults to the parent of the root.
- `LOONGSHIELD_LUA_LSM_CONFIG_FILE`: kernel config used by `doctor`.
- `LOONGSHIELD_LUA_LSM_ASSUME_CAP_MAC_ADMIN`: test-only capability bypass.

## Kernel Requirements

The running kernel must provide:

```text
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_LUA=y
CONFIG_SECURITY_LUA_LSM=y
CONFIG_LSM=...,lua,...
```

The `load` and `unload` commands require effective `CAP_MAC_ADMIN`, matching the
kernel-side securityfs write check.

## Examples

```sh
loongshield lua-lsm doctor
loongshield lua-lsm status
loongshield lua-lsm list
loongshield lua-lsm load /etc/loongshield/lua-lsm/policies.d/deny_tmp_marker.lua
loongshield lua-lsm unload deny_tmp_marker
```

## Exit Codes

- `0`: command completed successfully.
- `1`: CLI error, readiness failure, missing ABI file, validation failure, missing capability, or kernel write failure.
