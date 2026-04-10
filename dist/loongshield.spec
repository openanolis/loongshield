%global anolis_release 4
%global _debugsource_template %{nil}
%global debug_package %{nil}

Name: loongshield
Version: %{!?pkg_version:1.1.3}%{?pkg_version}
Release: %{anolis_release}%{?dist}
Summary: security shield framework for alinux/anolis
Group: Development/Tools

License: MIT AND BSD-2-Clause AND BSD-3-Clause AND Apache-2.0 AND curl AND LGPL-2.1-or-later
Source0: %{name}-%{version}.tar.gz
# Keep these vendored SourceN entries in sync with dist/rpm-vendor-sources.txt.
%global vendor_curl_commit 5ce164e0e9290c96eb7d502173426c0a135ec008
%global vendor_kmod_commit 9522b7b06670792a3cc08001dd021e8ce775b61e
%global vendor_libbpf_commit 02724cfd0702c4102138e62c3ae7d2721c7b190e
%global vendor_libcap_commit 542d7d86ecd2129dd5fe7e5b31ba307304f5b319
%global vendor_libuv_commit 0c1fa696aa502eb749c2c4735005f41ba00a27b8
%global vendor_lpeg_commit 118811c7f6a4375e2b4532fa5f4cadb87cdf6cd6
%global vendor_lua_cjson_commit e8972ac754788d3ef10a57a36016d6c3e85ba20d
%global vendor_lua_compat_5_3_commit 8f8e4c6adb43e107f5902e784ef207dc3c8ca06b
%global vendor_lua_curlv3_commit 563b1821d15a2076698e114f56695b22674a09ce
%global vendor_lua_auxiliar_commit 32bf4073ebbd949ef76bbfdd0e973d735a70526d
%global vendor_lua_openssl_commit 36a2aa51518a518909df6d729a366beb0d260021
%global vendor_luafilesystem_commit 912e06714fc276c15b4d5d1b42bd2b11edb8deff
%global vendor_luajit_commit 41fb94defa8f830ce69a8122b03f6ac3216d392a
%global vendor_luaposix_commit f12f957224d12257c882f43fde5cc442bdf44002
%global vendor_luasocket_commit e3ca4a767a68d127df548d82669aba3689bd84f4
%global vendor_luv_commit ebc79ee5aa082f90e53f75f3f326dcea11e8478d
%global vendor_lyaml_commit 37a9e51e82848f718eafbe95d261377130dcdd3f
%global vendor_openssl_commit cb8e64131e7ce230a9268bdd7cc4664868ff0dc9
Source1: curl-%{vendor_curl_commit}.tar.gz
Source2: kmod-%{vendor_kmod_commit}.tar.gz
Source3: libbpf-%{vendor_libbpf_commit}.tar.gz
Source4: libcap-%{vendor_libcap_commit}.tar.gz
Source5: libuv-%{vendor_libuv_commit}.tar.gz
Source6: lpeg-%{vendor_lpeg_commit}.tar.gz
Source7: lua-cjson-%{vendor_lua_cjson_commit}.tar.gz
Source8: lua-compat-5.3-%{vendor_lua_compat_5_3_commit}.tar.gz
Source9: lua-curlv3-%{vendor_lua_curlv3_commit}.tar.gz
Source10: lua-auxiliar-%{vendor_lua_auxiliar_commit}.tar.gz
Source11: lua-openssl-%{vendor_lua_openssl_commit}.tar.gz
Source12: luafilesystem-%{vendor_luafilesystem_commit}.tar.gz
Source13: luajit-%{vendor_luajit_commit}.tar.gz
Source14: luaposix-%{vendor_luaposix_commit}.tar.gz
Source15: luasocket-%{vendor_luasocket_commit}.tar.gz
Source16: luv-%{vendor_luv_commit}.tar.gz
Source17: lyaml-%{vendor_lyaml_commit}.tar.gz
Source18: openssl-%{vendor_openssl_commit}.tar.gz

BuildRequires:  cmake
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  systemd-devel
BuildRequires:  systemd
BuildRequires:  audit-libs-devel
BuildRequires:  dbus-devel
BuildRequires:  elfutils-libelf-devel
BuildRequires:  libarchive-devel
BuildRequires:  libattr-devel
BuildRequires:  libcap-devel
BuildRequires:  libcurl-devel
BuildRequires:  libmount-devel
BuildRequires:  libpsl-devel
BuildRequires:  libyaml-devel
BuildRequires:  libzstd-devel
BuildRequires:  openssl-devel
BuildRequires:  rpm-devel
BuildRequires:  xz-devel
BuildRequires:  perl-IPC-Cmd
BuildRequires:  perl-FindBin
BuildRequires:  perl-ExtUtils-MakeMaker
BuildRequires:  which
%description
security shield framework for alinux/anolis

%prep
%setup -q

unpack_vendor() {
    archive="$1"
    dest="$2"
    rm -rf "$dest"
    mkdir -p "$dest"
    tar -xzf "$archive" -C "$dest" --strip-components=1
}

unpack_vendor %{SOURCE1} deps/curl/curl
unpack_vendor %{SOURCE2} deps/kmod/kmod
unpack_vendor %{SOURCE3} deps/libbpf/libbpf
unpack_vendor %{SOURCE4} deps/libcap/libcap
unpack_vendor %{SOURCE5} deps/libuv/libuv
unpack_vendor %{SOURCE6} deps/lpeg/lpeg
unpack_vendor %{SOURCE7} deps/lua-cjson/lua-cjson
unpack_vendor %{SOURCE8} deps/lua-compat-5.3/lua-compat-5.3
unpack_vendor %{SOURCE9} deps/lua-curl/Lua-cURLv3
unpack_vendor %{SOURCE10} deps/lua-openssl/lua-auxiliar
unpack_vendor %{SOURCE11} deps/lua-openssl/lua-openssl
unpack_vendor %{SOURCE12} deps/luafilesystem/luafilesystem
unpack_vendor %{SOURCE13} deps/luajit/luajit
unpack_vendor %{SOURCE14} deps/luaposix/luaposix
unpack_vendor %{SOURCE15} deps/luasocket/luasocket
unpack_vendor %{SOURCE16} deps/luv/luv
unpack_vendor %{SOURCE17} deps/lyaml/lyaml
unpack_vendor %{SOURCE18} deps/openssl/openssl

%build
mkdir build
cd build
# Clear RPM hardened flags that break LuaJIT architecture detection
# LuaJIT handles its own optimization and security flags
unset CFLAGS CXXFLAGS FFLAGS FCFLAGS LDFLAGS
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DLOONGSHIELD_VERSION:STRING=%{version} \
    -DLOONGSHIELD_COMMIT:STRING=%{!?pkg_commit:unknown}%{?pkg_commit}
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}%{_sbindir}
install -d -m 0755 %{buildroot}%{_sysconfdir}/loongshield/seharden
install -d -m 0755 %{buildroot}%{_licensedir}/%{name}
install -d -m 0755 %{buildroot}%{_licensedir}/%{name}/third-party
install -m 0755 build/src/daemon/loongshield %{buildroot}%{_sbindir}/
install -m 0755 build/src/daemon/loonjit %{buildroot}%{_sbindir}/
install -m 0644 profiles/seharden/*.yml %{buildroot}%{_sysconfdir}/loongshield/seharden/
install -m 0644 LICENSE %{buildroot}%{_licensedir}/%{name}/
install -m 0644 THIRD_PARTY_LICENSES.md %{buildroot}%{_licensedir}/%{name}/
install -m 0644 LICENSES/QUEUE-BSD-3-Clause.txt %{buildroot}%{_licensedir}/%{name}/third-party/
install -m 0644 LICENSES/TREE-BSD-2-Clause.txt %{buildroot}%{_licensedir}/%{name}/third-party/
install -m 0644 LICENSES/LPeg-MIT.txt %{buildroot}%{_licensedir}/%{name}/third-party/
install -m 0644 deps/luajit/luajit/COPYRIGHT %{buildroot}%{_licensedir}/%{name}/third-party/LuaJIT-COPYRIGHT
install -m 0644 deps/libuv/libuv/LICENSE %{buildroot}%{_licensedir}/%{name}/third-party/libuv-LICENSE
install -m 0644 deps/luv/luv/LICENSE.txt %{buildroot}%{_licensedir}/%{name}/third-party/luv-LICENSE.txt
install -m 0644 deps/lyaml/lyaml/LICENSE %{buildroot}%{_licensedir}/%{name}/third-party/lyaml-LICENSE
install -m 0644 deps/lua-cjson/lua-cjson/LICENSE %{buildroot}%{_licensedir}/%{name}/third-party/lua-cjson-LICENSE
install -m 0644 deps/luafilesystem/luafilesystem/LICENSE %{buildroot}%{_licensedir}/%{name}/third-party/luafilesystem-LICENSE
install -m 0644 deps/lua-openssl/lua-openssl/LICENSE %{buildroot}%{_licensedir}/%{name}/third-party/lua-openssl-LICENSE
install -m 0644 deps/openssl/openssl/LICENSE.txt %{buildroot}%{_licensedir}/%{name}/third-party/openssl-LICENSE.txt
install -m 0644 deps/curl/curl/COPYING %{buildroot}%{_licensedir}/%{name}/third-party/curl-COPYING
install -m 0644 deps/lua-curl/Lua-cURLv3/LICENSE %{buildroot}%{_licensedir}/%{name}/third-party/lua-curl-LICENSE
install -m 0644 deps/kmod/kmod/COPYING %{buildroot}%{_licensedir}/%{name}/third-party/libkmod-COPYING
install -m 0644 deps/libcap/libcap/cap/License %{buildroot}%{_licensedir}/%{name}/third-party/libcap-cap-License
install -m 0644 deps/libcap/libcap/psx/License %{buildroot}%{_licensedir}/%{name}/third-party/libcap-psx-License
install -m 0644 deps/luaposix/luaposix/LICENSE %{buildroot}%{_licensedir}/%{name}/third-party/luaposix-LICENSE
install -m 0644 deps/libbpf/libbpf/LICENSE %{buildroot}%{_licensedir}/%{name}/third-party/libbpf-LICENSE
install -m 0644 deps/libbpf/libbpf/LICENSE.BSD-2-Clause %{buildroot}%{_licensedir}/%{name}/third-party/libbpf-LICENSE.BSD-2-Clause
install -m 0644 deps/luasocket/luasocket/LICENSE %{buildroot}%{_licensedir}/%{name}/third-party/luasocket-LICENSE

%files
%{_sbindir}/loongshield
%{_sbindir}/loonjit
%dir %{_sysconfdir}/loongshield
%dir %{_sysconfdir}/loongshield/seharden
%config(noreplace) %{_sysconfdir}/loongshield/seharden/*.yml
%license %{_licensedir}/%{name}/LICENSE
%license %{_licensedir}/%{name}/THIRD_PARTY_LICENSES.md
%license %{_licensedir}/%{name}/third-party/*

%changelog
* Wed Apr  8 2026 Zongyao Chen - 1.1.3-1
- Add public governance and release process documents for the open-source release line.
- Refresh README/docs structure and codify 1.x compatibility expectations.
- Improve build and CI portability across supported EL9 and arm64 environments.
- Refactor SEHarden internals to share schema, parser, loader, and output helpers.
- Fix rule-schema validation so inactive rules with newer comparators do not break other levels.

* Thu Mar 26 2026 Zongyao Chen - 1.1.2-1
- Improve SEHarden scan diagnostics and human-friendly verbose reporting.
- Split operator verbose output from developer debug tracing.
- Expand SEHarden profile and probe coverage with additional regression tests.
- Clean up make help output and document test-quick in the main target list.

* Fri Mar 13 2026 Zongyao Chen - 1.1.1-1
- Add AgentOS security baseline profile (agentos_baseline.yml) with 23 rules.
- Fix mounts enforcer: treat missing fstab entry as warning, not error.
- Fix agentos_baseline: correct absent-service detection and add kmod loaded checks.

* Fri Mar 13 2026 Zongyao Chen - 1.1.0-1
- Implement SEHarden reinforce mode with declarative remediation.
- Add enforcer modules: kmod, sysctl, services, permissions, file, mounts, packages.
- Add enforcerloader with module caching, symmetric to probeloader.
- Add --dry-run flag; re-audit after enforcement to confirm FIXED/FAILED-TO-FIX.
- Add reinforce sections to CIS ALinux 3 profile (kmod + ASLR sysctl rules).
- Fix probe cache invalidation before re-audit via reset_caches().
- Expand unit test coverage for all enforcer modules and reinforce engine logic.

* Tue Sep 16 2025 Zongyao Chen - 1.0.0-1
- Major refactor for 1.0.0 release.
- refactor seharden module.

* Mon Jun 9 2025 Tianjia Zhang - 0.1-2
- Update spec file

* Wed Sep 4 2024 Yilin Li - 0.1-1
- Init package.
