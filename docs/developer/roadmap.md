# Developer Roadmap

This file tracks medium-term engineering work.

## Lua C Modules

- lua-openscap
- lua-keyutils
- lua for LSM (selinux/smack/tomoyo/apparmor)
- lua-seccomp
- lua-libbpf (ebpf LSM)
- lua rpm/deb/portage
- lua-systemd: new API, async send.
- lua-kmod: ko verify.
- lua-mount: mount/umount context.
- embedded fanotify to libuv

## Security Base

- daemon
- config
- Web UI

## Security Functions

- Security harden (dengbao3/4, CIS)
- CVE scanner
- `loongshield vuln scan`: detect installed package exposure against CVE/advisory feeds, reusing the current RPM inventory and SBOM-oriented verification path where possible.
- SDK interface
