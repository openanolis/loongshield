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
- `import-key <pub.pem>`: import an SM2 public key into the local trust store.
- `keys`: list trusted SM2 public keys.
- `load <policy.lua>`: validate and load a Lua-LSM policy; verify its embedded
  signature when `--appraise` is given.
- `sign <policy.lua>`: sign a policy in place with an SM2 private key using the
  SM3 digest.
- `unload <name>`: write the module name to `unregister`.
- `hooks`: print `lsm_funcs` when `CONFIG_SECURITY_LUA_LSM_STATS=y`.
- `stats`: print VM/cache stats when `CONFIG_SECURITY_LUA_LSM_STATS=y`.

## Options

- `--root <path>`: override the Lua-LSM securityfs root.
- `--config <path>`: override the kernel config path used by `doctor`.
- `--key <path>`: SM2 private key used by `sign`.
- `--appraise <mode>`: policy appraisal mode, `off`, `log`, or `enforce`.
  Defaults to `off`; verification runs only when an appraisal mode is given.
- `--trust-dir <path>`: override the trusted public key directory.
- `--no-validate`: skip userspace policy metadata validation before `load`.
- `--log-level <level>`: set log level.
- `-h`, `--help`: show command help.

## Policy Storage Integrity

Policies are protected against on-disk tampering with embedded SM2 signatures
over the SM3 digest. The design follows kernel module signatures and RPM
signatures: the signature is stored at the end of the policy file itself, and
verification uses keys from a local trust store, like `rpm --import`. Appraisal
modes follow IMA: `off`, `log`, and `enforce`.

1. Create an SM2 key pair:

```sh
openssl ecparam -name SM2 -genkey -noout -out sm2.key
openssl ec -in sm2.key -pubout -out sm2.pub
```

2. Import the public key once, like `rpm --import`:

```sh
loongshield lua-lsm import-key sm2.pub
```

3. Sign a policy:

```sh
loongshield lua-lsm sign profiles/lua-lsm/deny_tmp_marker.lua --key sm2.key
```

4. Load with verification. Verification is opt-in, like IMA without
`ima_appraise` configured:

```sh
loongshield lua-lsm load profiles/lua-lsm/deny_tmp_marker.lua --appraise enforce
```

By default (`off`), verification is skipped entirely, like `ima_appraise=off`.
In `log` mode, failures are logged but the load continues. In `enforce` mode, a
missing, invalid, or untrusted signature fails with exit code 1 and the policy
is not written to `register`.

After verification, `load` strips the signature trailer and writes only the
clean Lua source to `register`; the kernel-side Lua-LSM is unaware of the
signature format.

## Environment

- `LOONGSHIELD_LUA_LSM_SECURITYFS_ROOT`: defaults to `/sys/kernel/security/lua`.
- `LOONGSHIELD_LUA_LSM_SECURITYFS_MOUNT`: defaults to the parent of the root.
- `LOONGSHIELD_LUA_LSM_CONFIG_FILE`: kernel config used by `doctor`.
- `LOONGSHIELD_LUA_LSM_ASSUME_CAP_MAC_ADMIN`: test-only capability bypass.
- `LOONGSHIELD_LUA_LSM_PUBKEY_DIR`: trusted public key directory, defaults to
  `/var/lib/loongshield/lua-lsm/pubkeys`.
- `LOONGSHIELD_LUA_LSM_APPRAISE`: appraisal mode, defaults to `off`.

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
loongshield lua-lsm import-key sm2.pub
loongshield lua-lsm keys
loongshield lua-lsm sign profiles/lua-lsm/deny_tmp_marker.lua --key sm2.key
loongshield lua-lsm load profiles/lua-lsm/deny_tmp_marker.lua --appraise enforce
loongshield lua-lsm load profiles/lua-lsm/deny_tmp_marker.lua --appraise log
loongshield lua-lsm load profiles/lua-lsm/deny_tmp_marker.lua
loongshield lua-lsm unload deny_tmp_marker
```

## Exit Codes

- `0`: command completed successfully.
- `1`: CLI error, readiness failure, missing ABI file, validation failure, missing capability, kernel write failure, or failed signature verification in `enforce` mode.
