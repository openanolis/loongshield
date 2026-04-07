# Submodule Sources

Loongshield vendors a number of third-party dependencies through git submodules.
Every release is expected to build from a fresh recursive clone, so any
submodule URL that does not point at an obvious official upstream needs an
explicit explanation.

## Policy

- Prefer official upstream repositories when the pinned commit is available there.
- Keep a fork URL only when the pinned commit is not currently available from the
  canonical upstream, or when the project intentionally depends on fork-only
  maintenance.
- Re-check retained fork URLs whenever a dependency is updated for release.

## Retained Fork-Backed Submodules

These entries still point at public forks on purpose.

| Path | Current URL | Pinned commit | Canonical upstream | Why it stays this way | Maintenance expectation |
| --- | --- | --- | --- | --- | --- |
| `deps/kmod/kmod` | `https://github.com/auacc/kmod.git` | `9522b7b06670792a3cc08001dd021e8ce775b61e` | `https://github.com/kmod-project/kmod.git` | The pinned object currently resolves to `remotes/origin/auacc` in this checkout and is not contained in the locally configured upstream refs. Changing the URL without re-pinning would risk breaking fresh recursive clones. | Keep the fork pin until a matching upstream commit or release is verified, then switch `.gitmodules` to the canonical upstream. |
| `deps/lpeg/lpeg` | `https://github.com/auacc/lpeg.git` | `118811c7f6a4375e2b4532fa5f4cadb87cdf6cd6` | Canonical upstream not configured in this checkout | The current dependency pin comes from the fork's `origin/master`, and this checkout does not include a separate upstream remote that proves the same object is publicly available elsewhere. | Re-evaluate on every dependency refresh and move to a canonical upstream URL once a matching public source is confirmed. |
| `deps/lua-curl/Lua-cURLv3` | `https://github.com/auacc/Lua-cURLv3.git` | `563b1821d15a2076698e114f56695b22674a09ce` | `https://github.com/Lua-cURL/Lua-cURLv3.git` | The pinned object currently resolves to the fork's `remotes/origin/compat53` and is not contained in the locally configured upstream refs. The fork is therefore part of the reproducible source chain today. | Keep the fork pin until the required compat53 changes are available upstream, or re-pin to a verified upstream commit before release. |

## Personal-Namespace Upstreams

Some submodules live under an individual maintainer's public namespace, but in
this repository they are treated as their normal public upstream, not as
Loongshield-specific carry forks.

- `deps/lua-openssl/lua-openssl` and `deps/lua-openssl/lua-auxiliar`
- `deps/lyaml/lyaml`
- `deps/lua-cjson/lua-cjson`

If any of those repositories stop acting as the practical upstream for the
dependency, move them into the table above and document the fork status
explicitly.

## Normalized To Official Upstream

- `deps/libcap/libcap` now uses `https://kernel.googlesource.com/pub/scm/libs/libcap/libcap`.
  The previous `.gitmodules` entry pointed at `sailfishos-mirror/libcap`, and a
  later open-source cleanup switched it to `git.kernel.org`. The repository
  metadata now uses the googlesource mirror of the same upstream because it is
  more reachable in some environments while preserving the same pinned commit.
