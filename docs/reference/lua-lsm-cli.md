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

- `status`: show kernel readiness, trusted keys, and loaded modules. Supports
  `--json` for machine-readable reporting.
- `import-key <pub.pem>`: import an SM2 public key into the local trust store.
- `load <policy.lua | directory>`: verify, validate, and load a single policy
  or every `.lua` policy in a directory, in filename order.
- `sign <policy.lua>`: sign a policy in place with an SM2 private key using the
  SM3 digest.
- `unload <name>`: write the module name to `unregister`.

## Options

- `--root <path>`: override the Lua-LSM securityfs root.
- `--config <path>`: override the kernel config path used by `status`.
- `--key <path>`: SM2 private key used by `sign`.
- `--appraise <mode>`: policy appraisal mode, `off`, `log`, or `enforce`.
  Defaults to `off`; verification runs only when an appraisal mode is given.
- `--trust-dir <path>`: override the trusted public key directory.
- `--json`: machine-readable `status` output.
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

## Directory Loading

`load` accepts a policy directory, like `sudoers.d` or `sysctl.d`. The
directory itself is the policy list; file presence enables a policy, file
removal disables it, and numeric prefixes control order:

```
policies/
├── 01-deny_tmp_marker.lua
└── 02-protect_home.lua
```

Only `*.lua` files load, in filename order. A load failure aborts the
directory. Distributing the same signed directory to many hosts and loading it
on each gives every host the same policy set, which is the consistency
guarantee for distributing policies across machines.

## Distributing Policies

Use the generic `loongshield filedist` command to distribute signed policy
files. The initial public key import is a trust decision and must happen out of
band (hand-delivered, verified channel, or pre-provisioned image):

```sh
loongshield lua-lsm import-key /etc/loongshield/sm2.pub
```

On the management host:

```sh
loongshield filedist server --port 8080 \
  --dir /srv/loongshield/lua-lsm
```

On each managed host:

```sh
loongshield filedist pull http://management:8080/ \
  --dir /etc/loongshield/lua-lsm
loongshield lua-lsm load /etc/loongshield/lua-lsm/policies \
  --appraise enforce
```

`filedist` is transport only. It has no signature or key knowledge. Lua-LSM
policy integrity comes from the embedded SM2 signature checked by
`load --appraise enforce`, not from the transport. See
[filedist-cli.md](./filedist-cli.md) for its limits.

## Environment

- `LOONGSHIELD_LUA_LSM_SECURITYFS_ROOT`: defaults to `/sys/kernel/security/lua`.
- `LOONGSHIELD_LUA_LSM_SECURITYFS_MOUNT`: defaults to the parent of the root.
- `LOONGSHIELD_LUA_LSM_CONFIG_FILE`: kernel config used by `status`.
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
loongshield lua-lsm status
loongshield lua-lsm status --json
loongshield lua-lsm import-key sm2.pub
loongshield lua-lsm sign profiles/lua-lsm/deny_tmp_marker.lua --key sm2.key
loongshield lua-lsm load profiles/lua-lsm/deny_tmp_marker.lua --appraise enforce
loongshield lua-lsm load profiles/lua-lsm/ --appraise enforce
loongshield lua-lsm load profiles/lua-lsm/deny_tmp_marker.lua --appraise log
loongshield lua-lsm load profiles/lua-lsm/deny_tmp_marker.lua
loongshield lua-lsm unload deny_tmp_marker
```

## Exit Codes

- `0`: command completed successfully.
- `1`: CLI error, readiness failure, missing ABI file, validation failure, missing capability, kernel write failure, or failed signature verification in `enforce` mode.
