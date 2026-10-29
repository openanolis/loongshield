# Lua-LSM Native Support

Lua-LSM is a kernel-provided built-in Linux Security Module. Loongshield treats
it as a runtime capability exposed through securityfs, not as another
out-of-tree kernel module under `src/kmod/`.

## Boundary

Loongshield owns:

- readiness checks for the running kernel
- policy validation before explicit load
- embedded SM2/SM3 policy signatures and appraisal
- policy verification, validation, loading, and unloading
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

## Policy Storage Integrity

Lua-LSM policies are access-control information, so they can be protected
against on-disk tampering before they are pushed into the kernel. The design
follows kernel module signatures, RPM signatures, and IMA appraisal:

- A policy file is signed in place with an SM2 private key over the SM3 digest,
  like `rpm --addsign`. The signature is embedded at the end of the policy file
  in a trailer with a magic marker, algorithm id, and signature length, like
  Linux module signatures.
- `loongshield lua-lsm import-key <sm2-public.pem>` imports a verification key
  into a local trust store (`/var/lib/loongshield/lua-lsm/pubkeys`), like
  `rpm --import`. Keys are identified by the SM3 digest of the stored key
  material.
- `loongshield lua-lsm load <policy.lua>` splits the embedded signature from
  the source, verifies it against every trusted key, validates metadata, and
  writes only the clean source to `register`. The kernel-side Lua-LSM is
  unaware of the signature format.
- Appraisal modes follow IMA: `off` (default) skips verification, like
  `ima_appraise=off`; `log` records failures but continues; `enforce` rejects
  unsigned, invalid, or untrusted signatures. Verification runs only when an
  appraisal mode is selected with `--appraise` or
  `LOONGSHIELD_LUA_LSM_APPRAISE`.

The bundled `lua-openssl` binding provides SM2 signing and verification
(`pkey:sign`/`pkey:verify` with the SM3 digest), so no new runtime dependency
is required. The default SM2 user identifier is the standard
`1234567812345678`.

The trust store directory is part of the protected boundary: an attacker who
can modify both the policy and the trusted keys can replace both. Production
deployments should place the trust directory on the same integrity-protected
 footing as the rest of the LoongShield installation.

## Distributing Policies

Policy files are distributed by the generic `filedist` command. Managed hosts
pull the same directory, import the verification key out of band, and load the
directory with `--appraise enforce`, which is the multi-host consistency
mechanism: every host verifies the same SM2 signatures over the same policy
set. `filedist` is intentionally transport-only and has no Lua-LSM-specific
trust model; see its reference documentation for limits.

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
status, load, unload, sign, and import-key behavior without requiring
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
