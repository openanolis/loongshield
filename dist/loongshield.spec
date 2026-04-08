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
BuildRequires:  git

%description
security shield framework for alinux/anolis

%prep
%setup -q

%build
mkdir build
cd build
# Clear RPM hardened flags that break LuaJIT architecture detection
# LuaJIT handles its own optimization and security flags
unset CFLAGS CXXFLAGS FFLAGS FCFLAGS LDFLAGS
cmake .. -DCMAKE_BUILD_TYPE=Release
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
