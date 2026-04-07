# Third-Party Licenses

This file tracks third-party code that is either copied into this repository
outside `deps/` or statically linked into `loongshield` and `loonjit`.

It is intentionally narrower than a full source tree inventory. Dynamic system
libraries are not listed here. Test fixtures, helper data, and nested upstream
test assets that are not part of the shipped binaries are also out of scope.

## Directly Carried Source Files

These files live under `src/` and are not original Loongshield code.

| Path | Origin | License | Packaged notice |
| --- | --- | --- | --- |
| `src/lib/queue.h` | BSD queue macros carried from BSD-derived systems | BSD-3-Clause | `LICENSES/QUEUE-BSD-3-Clause.txt` |
| `src/lib/tree.h` | BSD tree macros carried from NetBSD/OpenBSD/FreeBSD lineage | BSD-2-Clause | `LICENSES/TREE-BSD-2-Clause.txt` |
| `src/daemon/modules/lyaml/*.lua` | `lyaml` Lua modules by Gary V. Vaughan | MIT | `deps/lyaml/lyaml/LICENSE` |

## Statically Linked Dependencies

The main runtime currently links the following vendored libraries statically.

| Component | Source path | License used for this package | Upstream notice source |
| --- | --- | --- | --- |
| LuaJIT | `deps/luajit/luajit` | MIT | `deps/luajit/luajit/COPYRIGHT` |
| libuv | `deps/libuv/libuv` | MIT | `deps/libuv/libuv/LICENSE` |
| luv | `deps/luv/luv` | Apache-2.0 | `deps/luv/luv/LICENSE.txt` |
| lyaml / libyaml binding | `deps/lyaml/lyaml` | MIT | `deps/lyaml/lyaml/LICENSE` |
| lua-cjson | `deps/lua-cjson/lua-cjson` | MIT | `deps/lua-cjson/lua-cjson/LICENSE` |
| LuaFileSystem | `deps/luafilesystem/luafilesystem` | MIT | `deps/luafilesystem/luafilesystem/LICENSE` |
| lua-openssl | `deps/lua-openssl/lua-openssl` | MIT | `deps/lua-openssl/lua-openssl/LICENSE` |
| OpenSSL | `deps/openssl/openssl` | Apache-2.0 | `deps/openssl/openssl/LICENSE.txt` |
| curl | `deps/curl/curl` | curl | `deps/curl/curl/COPYING` |
| Lua-cURLv3 | `deps/lua-curl/Lua-cURLv3` | MIT | `deps/lua-curl/Lua-cURLv3/LICENSE` |
| LPeg | `deps/lpeg/lpeg` | MIT | `deps/lpeg/lpeg/lpeg.html` |
| libkmod | `deps/kmod/kmod` | LGPL-2.1-or-later | `deps/kmod/kmod/COPYING` and `deps/kmod/kmod/README.md` |
| libcap (`cap`) | `deps/libcap/libcap` | BSD-3-Clause | `deps/libcap/libcap/cap/License` |
| libcap (`psx`) | `deps/libcap/libcap` | BSD-3-Clause | `deps/libcap/libcap/psx/License` |
| luaposix | `deps/luaposix/luaposix` | MIT | `deps/luaposix/luaposix/LICENSE` |
| libbpf | `deps/libbpf/libbpf` | BSD-2-Clause | `deps/libbpf/libbpf/LICENSE` and `deps/libbpf/libbpf/LICENSE.BSD-2-Clause` |
| LuaSocket | `deps/luasocket/luasocket` | MIT | `deps/luasocket/luasocket/LICENSE` |

## Notes

- `libbpf` is distributed upstream under `LGPL-2.1 OR BSD-2-Clause`. This
  package uses the permissive `BSD-2-Clause` option and installs the BSD notice.
- `libcap` and `psx` are distributed upstream under `BSD-3-Clause OR GPL-2.0-only`.
  This package uses the permissive `BSD-3-Clause` option and installs the BSD notice.
- `libkmod` is linked statically and is licensed upstream as `LGPL-2.1-or-later`
  for the library code used here. The vendored source remains present in the
  source tree and source tarball under `deps/kmod/kmod/`.
- LPeg does not ship a standalone `LICENSE` file in this checkout. A packaged
  notice file is extracted from the upstream license section in `lpeg.html`.

## Binary Package Layout

The RPM installs:

- the project root `LICENSE`
- this `THIRD_PARTY_LICENSES.md` inventory
- extracted notices for directly carried BSD source files and LPeg
- upstream license files for statically linked third-party components

All of those files are installed under `%{_licensedir}/loongshield/`.
