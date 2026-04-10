SHELL := /bin/bash
.SHELLFLAGS := -ec

PROJECT := loongshield
VERSION := $(shell tr -d '\n' < VERSION 2>/dev/null || echo 0.0.0)
SRC_DIR := $(abspath .)
O ?= build
BUILD_DIR := $(abspath $(O))
JOBS ?= $(shell nproc 2>/dev/null || echo 4)
CMAKE_FLAGS ?=
ENV_CHECK_DEP := $(if $(filter 1,$(ALLOW_UNSUPPORTED_HOST)),,env-check)

RPM_SPEC := $(SRC_DIR)/dist/loongshield.spec
RPM_SOURCE_SCRIPT := $(SRC_DIR)/dist/scripts/rpm-sources.sh
RPM_SOURCE_OUTPUT_DIR := $(SRC_DIR)/dist
RPM_BUILD_ROOT := $(BUILD_DIR)/rpmbuild
RPM_TMPDIR := $(RPM_BUILD_ROOT)/tmp
RELEASE_ARTIFACT_DIR := $(BUILD_DIR)/release-artifacts
SOURCE_BUNDLE_NAME := $(PROJECT)-$(VERSION)-rpm-source-bundle
SOURCE_BUNDLE_DIR := $(RELEASE_ARTIFACT_DIR)/$(SOURCE_BUNDLE_NAME)
SOURCE_BUNDLE_ARCHIVE := $(RELEASE_ARTIFACT_DIR)/$(SOURCE_BUNDLE_NAME).tar.gz
RPM_BUILD_REQUIRES := \
	audit-libs-devel \
	cmake \
	dbus-devel \
	elfutils-libelf-devel \
	gcc \
	gcc-c++ \
	git \
	libarchive-devel \
	libattr-devel \
	libcap-devel \
	libcurl-devel \
	libmount-devel \
	libpsl-devel \
	libyaml-devel \
	libzstd-devel \
	make \
	openssl-devel \
	perl-ExtUtils-MakeMaker \
	perl-FindBin \
	perl-IPC-Cmd \
	rpm-build \
	rpm-devel \
	rpmdevtools \
	systemd \
	systemd-devel \
	which \
	xz-devel
GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
RPM_DEFINES := \
	--define "_topdir $(RPM_BUILD_ROOT)" \
	--define "_tmppath $(RPM_TMPDIR)" \
	--define "pkg_version $(VERSION)" \
	--define "pkg_commit $(GIT_COMMIT)"

DOCKER_IMAGE := loongshield-dev:latest
DOCKER_SERVER_API_VERSION := $(shell docker version --format '{{.Server.APIVersion}}' 2>/dev/null)
DOCKER_API_ENV := $(if $(strip $(DOCKER_SERVER_API_VERSION)),DOCKER_API_VERSION=$(DOCKER_SERVER_API_VERSION))

SUBMODULE_SENTINELS := \
	deps/luajit/luajit/src/lua.h \
	deps/libuv/libuv/src/unix/async.c \
	deps/lpeg/lpeg/lpcap.c \
	deps/lua-openssl/lua-auxiliar/auxiliar.c \
	deps/lua-openssl/lua-openssl/src/openssl.c \
	deps/libcap/libcap/libcap/cap_alloc.c

.PHONY: all \
	bootstrap build configure submodules \
	test test-quick test-integration \
	kmod install \
	buildreqs env-check \
	rpm-sources source-bundle rpm rpm-srpm srpm-in-docker release-assets \
	docker-dev docker-run-dev rpm-in-docker \
	clean distclean help

all: build

bootstrap:
	@echo "==> Installing build requirements"
	@$(MAKE) --no-print-directory ALLOW_UNSUPPORTED_HOST=1 buildreqs
	@echo "==> Building project"
	@$(MAKE) --no-print-directory ALLOW_UNSUPPORTED_HOST=1 build

configure: $(ENV_CHECK_DEP) submodules
	@cache_file="$(BUILD_DIR)/CMakeCache.txt"; \
	if [ -f "$$cache_file" ]; then \
		cache_src="$$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$$cache_file")"; \
		if [ "$$cache_src" != "$(SRC_DIR)" ]; then \
			echo "==> Removing stale build directory $(BUILD_DIR)"; \
			rm -rf "$(BUILD_DIR)"; \
		fi; \
	fi
	@cmake -S "$(SRC_DIR)" -B "$(BUILD_DIR)" $(CMAKE_FLAGS)

build: configure
	@cmake --build "$(BUILD_DIR)" --parallel "$(JOBS)"

test: build
	@"$(BUILD_DIR)/src/daemon/loonjit" "$(SRC_DIR)/tests/run.lua" --type all

test-quick:
	@"$(BUILD_DIR)/src/daemon/loonjit" "$(SRC_DIR)/tests/run.lua" --type all

test-integration: build
	@"$(BUILD_DIR)/src/daemon/loonjit" "$(SRC_DIR)/tests/run.lua" --type integration

kmod:
	@$(MAKE) -C "$(SRC_DIR)/src/kmod"

install: build
	@install -d -m 0755 "$(DESTDIR)$(PREFIX)/sbin"
	@install -d -m 0755 "$(DESTDIR)$(SYSCONFDIR)/loongshield/seharden"
	@install -d -m 0755 "$(DESTDIR)$(LICENSEDIR)/$(PROJECT)"
	@install -m 0755 "$(BUILD_DIR)/src/daemon/loongshield" "$(DESTDIR)$(PREFIX)/sbin/loongshield"
	@install -m 0755 "$(BUILD_DIR)/src/daemon/loonjit" "$(DESTDIR)$(PREFIX)/sbin/loonjit"
	@install -m 0644 "$(SRC_DIR)"/profiles/seharden/*.yml "$(DESTDIR)$(SYSCONFDIR)/loongshield/seharden/"
	@install -m 0644 "$(SRC_DIR)/LICENSE" "$(DESTDIR)$(LICENSEDIR)/$(PROJECT)/LICENSE"

PREFIX ?= /usr
SYSCONFDIR ?= /etc
LICENSEDIR ?= $(PREFIX)/share/licenses

buildreqs: $(ENV_CHECK_DEP)
	@pkg_mgr="$$(command -v dnf || command -v yum || true)"; \
	if [ -z "$$pkg_mgr" ]; then \
		echo "Error: neither dnf nor yum was found on this system." >&2; \
		exit 1; \
	fi; \
	sudo_cmd=""; \
	if [ "$$(id -u)" -ne 0 ]; then \
		sudo_cmd=sudo; \
	fi; \
	echo "==> Using package manager: $$pkg_mgr"; \
	$$sudo_cmd $$pkg_mgr install -y $(RPM_BUILD_REQUIRES)

env-check:
	@if [ "$${ALLOW_UNSUPPORTED_HOST:-0}" = "1" ]; then \
		echo "==> Skipping host compatibility checks"; \
		exit 0; \
	fi; \
	if [ "$$(uname -s)" != "Linux" ]; then \
		echo "Error: unsupported host OS '$$(uname -s)'. Use Linux or the Docker workflow." >&2; \
		exit 1; \
	fi; \
	arch="$$(uname -m)"; \
	case "$$arch" in \
		x86_64|aarch64|arm64) ;; \
		*) \
			echo "Error: unsupported host architecture '$$arch'. Supported architectures: x86_64, aarch64." >&2; \
			exit 1; \
			;; \
	esac; \
	if [ ! -f /etc/os-release ]; then \
		echo "Error: /etc/os-release not found. Cannot determine whether this host is supported." >&2; \
		exit 1; \
	fi; \
	. /etc/os-release; \
	case "$${PLATFORM_ID:-}" in \
		platform:el9|platform:an23|platform:alnx4) ;; \
		*) \
			echo "Error: unsupported local build host '$${PRETTY_NAME:-$${NAME:-unknown}}'." >&2; \
			echo "Supported local build hosts: CentOS Stream 9 / EL9-compatible, Anolis OS 23, Alibaba Cloud Linux 4." >&2; \
			echo "Use 'make docker-dev' or re-run with ALLOW_UNSUPPORTED_HOST=1 to bypass this check." >&2; \
			exit 1; \
			;; \
	esac; \
	if ! command -v dnf >/dev/null 2>&1 && ! command -v yum >/dev/null 2>&1; then \
		echo "Error: no supported package manager found. Expected dnf or yum on the local build host." >&2; \
		exit 1; \
	fi

rpm-sources: submodules
	@"$(RPM_SOURCE_SCRIPT)" build --repo-root "$(SRC_DIR)" --out-dir "$(RPM_SOURCE_OUTPUT_DIR)" --project "$(PROJECT)" --version "$(VERSION)"

source-bundle: rpm-sources
	@rm -rf "$(SOURCE_BUNDLE_DIR)" "$(SOURCE_BUNDLE_ARCHIVE)"
	@mkdir -p "$(SOURCE_BUNDLE_DIR)/SOURCES" "$(SOURCE_BUNDLE_DIR)/SPECS"
	@while IFS= read -r source_file; do \
		cp "$$source_file" "$(SOURCE_BUNDLE_DIR)/SOURCES/"; \
	done < <("$(RPM_SOURCE_SCRIPT)" list --repo-root "$(SRC_DIR)" --out-dir "$(RPM_SOURCE_OUTPUT_DIR)" --project "$(PROJECT)" --version "$(VERSION)")
	@cp "$(RPM_SPEC)" "$(SOURCE_BUNDLE_DIR)/SPECS/"
	@cp "$(SRC_DIR)/dist/rpm-vendor-sources.txt" "$(SOURCE_BUNDLE_DIR)/"
	@(cd "$(SOURCE_BUNDLE_DIR)" && sha256sum SOURCES/* SPECS/loongshield.spec rpm-vendor-sources.txt > SHA256SUMS)
	@mkdir -p "$(RELEASE_ARTIFACT_DIR)"
	@tar -C "$(RELEASE_ARTIFACT_DIR)" -czf "$(SOURCE_BUNDLE_ARCHIVE)" "$(SOURCE_BUNDLE_NAME)"

rpm: rpm-sources
	@mkdir -p "$(RPM_BUILD_ROOT)"/BUILD "$(RPM_BUILD_ROOT)"/RPMS "$(RPM_BUILD_ROOT)"/SOURCES "$(RPM_BUILD_ROOT)"/SPECS "$(RPM_BUILD_ROOT)"/SRPMS "$(RPM_TMPDIR)"
	@while IFS= read -r source_file; do \
		cp "$$source_file" "$(RPM_BUILD_ROOT)/SOURCES/"; \
	done < <("$(RPM_SOURCE_SCRIPT)" list --repo-root "$(SRC_DIR)" --out-dir "$(RPM_SOURCE_OUTPUT_DIR)" --project "$(PROJECT)" --version "$(VERSION)")
	@cp "$(RPM_SPEC)" "$(RPM_BUILD_ROOT)/SPECS/"
	@rpmbuild -bb $(RPM_DEFINES) "$(RPM_BUILD_ROOT)/SPECS/loongshield.spec"

rpm-srpm: rpm-sources
	@mkdir -p "$(RPM_BUILD_ROOT)"/BUILD "$(RPM_BUILD_ROOT)"/RPMS "$(RPM_BUILD_ROOT)"/SOURCES "$(RPM_BUILD_ROOT)"/SPECS "$(RPM_BUILD_ROOT)"/SRPMS "$(RPM_TMPDIR)"
	@while IFS= read -r source_file; do \
		cp "$$source_file" "$(RPM_BUILD_ROOT)/SOURCES/"; \
	done < <("$(RPM_SOURCE_SCRIPT)" list --repo-root "$(SRC_DIR)" --out-dir "$(RPM_SOURCE_OUTPUT_DIR)" --project "$(PROJECT)" --version "$(VERSION)")
	@cp "$(RPM_SPEC)" "$(RPM_BUILD_ROOT)/SPECS/"
	@rpmbuild -bs $(RPM_DEFINES) "$(RPM_BUILD_ROOT)/SPECS/loongshield.spec"

srpm-in-docker: docker-dev rpm-sources
	@mkdir -p "$(BUILD_DIR)/rpmbuild-docker"
	@$(DOCKER_API_ENV) docker run --rm \
		--network host \
		--user 0:0 \
		-v "$(SRC_DIR)":/workspace:ro \
		-v "$(BUILD_DIR)/rpmbuild-docker":/root/rpmbuild \
		-w /root \
		"$(DOCKER_IMAGE)" \
		/bin/bash -lc '\
			set -e; \
			mkdir -p ~/rpmbuild/tmp; \
			rpmdev-setuptree; \
			while IFS= read -r source_file; do \
				cp "$$source_file" ~/rpmbuild/SOURCES/; \
			done < <(/workspace/dist/scripts/rpm-sources.sh list --repo-root /workspace --out-dir /workspace/dist --project $(PROJECT) --version $(VERSION)); \
			cp /workspace/dist/loongshield.spec ~/rpmbuild/SPECS/; \
			rpmbuild -bs \
				--define "_tmppath %{getenv:HOME}/rpmbuild/tmp" \
				--define "pkg_version $(VERSION)" \
				--define "pkg_commit $(GIT_COMMIT)" \
				~/rpmbuild/SPECS/loongshield.spec; \
			ls -la ~/rpmbuild/SRPMS/ \
		'

release-assets: source-bundle srpm-in-docker

docker-dev: submodules
	@$(DOCKER_API_ENV) docker build \
		--network host \
		--build-arg CONTAINER_USER=$$(if [ $$(id -u) -eq 0 ]; then echo root; else echo developer; fi) \
		--build-arg USER_UID=$$(id -u) \
		--build-arg USER_GID=$$(id -g) \
		-t "$(DOCKER_IMAGE)" \
		-f "$(SRC_DIR)/Dockerfile" \
		"$(SRC_DIR)"

docker-run-dev: docker-dev
	@$(DOCKER_API_ENV) docker run --rm -it \
		--privileged \
		--network host \
		-e TERM="$${TERM:-xterm-256color}" \
		-e MAKEFLAGS="-j$$(nproc)" \
		-e O="build-docker" \
		-w /workspace \
		-v "$(SRC_DIR)":/workspace:cached \
		-v /workspace/build-docker \
		"$(DOCKER_IMAGE)" \
		/bin/bash

rpm-in-docker: docker-dev rpm-sources
	@mkdir -p "$(BUILD_DIR)/rpmbuild-docker"
	@$(DOCKER_API_ENV) docker run --rm \
		--network host \
		--user 0:0 \
		-v "$(SRC_DIR)":/workspace:ro \
		-v "$(BUILD_DIR)/rpmbuild-docker":/root/rpmbuild \
		-w /root \
		"$(DOCKER_IMAGE)" \
		/bin/bash -lc '\
			set -e; \
			mkdir -p ~/rpmbuild/tmp; \
			rpmdev-setuptree; \
			while IFS= read -r source_file; do \
				cp "$$source_file" ~/rpmbuild/SOURCES/; \
			done < <(/workspace/dist/scripts/rpm-sources.sh list --repo-root /workspace --out-dir /workspace/dist --project $(PROJECT) --version $(VERSION)); \
			cp /workspace/dist/loongshield.spec ~/rpmbuild/SPECS/; \
			rpmbuild -bb \
				--define "_tmppath %{getenv:HOME}/rpmbuild/tmp" \
				--define "pkg_version $(VERSION)" \
				--define "pkg_commit $(GIT_COMMIT)" \
				~/rpmbuild/SPECS/loongshield.spec; \
			ls -la ~/rpmbuild/RPMS/*/ \
		'

submodules:
	@missing_submodules=0; \
	for sentinel in $(SUBMODULE_SENTINELS); do \
		if [ ! -f "$$sentinel" ]; then \
			missing_submodules=1; \
			break; \
		fi; \
	done; \
	if [ "$$missing_submodules" -eq 1 ]; then \
		echo "==> Initializing git submodules"; \
		git submodule update --init --recursive; \
	fi; \
	for sentinel in $(SUBMODULE_SENTINELS); do \
		if [ ! -f "$$sentinel" ]; then \
			echo "Error: required vendored source is missing: $$sentinel" >&2; \
			exit 1; \
		fi; \
	done

clean:
	@if [ -d "$(BUILD_DIR)" ]; then \
		cmake --build "$(BUILD_DIR)" --target clean >/dev/null 2>&1 || true; \
	fi
	@rm -f "$(SRC_DIR)/src/daemon/bin_ramfs_luac.h" "$(SRC_DIR)/src/daemon/bin_initrd_tar.h"

distclean: clean
	@rm -rf "$(BUILD_DIR)"
	@rm -f "$(RPM_SOURCE_OUTPUT_DIR)"/*.tar.gz
	@$(MAKE) -C "$(SRC_DIR)/src/kmod" clean >/dev/null 2>&1 || true

help:
	@printf '%s\n' \
		'make                  Build the project' \
		'make bootstrap        Install build deps and build locally' \
		'make test             Build and run the full test suite' \
		'make test-quick       Re-run the full test suite without rebuilding' \
		'make test-integration Build and run integration tests' \
		'make kmod             Build the kernel module' \
		'make install          Install binaries and profiles into DESTDIR/PREFIX' \
		'make buildreqs        Install local RPM build requirements' \
		'make env-check        Validate the local host platform' \
		'make rpm-sources      Prepare Source0 plus vendor SourceN tarballs' \
		'make source-bundle    Build a release source bundle from Source0 plus SourceN' \
		'make rpm              Build a binary RPM locally' \
		'make rpm-srpm         Build a source RPM locally' \
		'make release-assets   Build release source assets (bundle + SRPM)' \
		'make docker-dev       Build the development container image' \
		'make docker-run-dev   Start an interactive development container' \
		'make rpm-in-docker    Build RPMs inside the development container' \
		'make clean            Clean build outputs' \
		'make distclean        Remove build outputs and generated tarballs'
