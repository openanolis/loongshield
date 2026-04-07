# Loongshield Build System
# ========================
# Linux kernel-style Makefile wrapping CMake
#
# Usage:
#   make              - Build everything (daemon + loonjit)
#   make bootstrap    - Install build deps, init submodules, then build
#   make help         - Show this help message
#   make test         - Run all test suites
#   make test-unit    - Run unit tests
#   make test-integration - Run integration tests
#   make test-e2e     - Run e2e tests
#   make test-quick   - Run all tests without rebuilding
#   make kmod         - Build kernel module
#   make install      - Build and install binaries + profiles directly
#   make uninstall    - Remove installed files
#   make rpm          - Build RPM packages
#   make rpm-install  - Build RPM and install via rpm -Uvh
#   make docker       - Build Docker images
#   make clean        - Clean build artifacts
#
# Variables:
#   V=1               - Verbose output
#   JOBS=N            - Parallel jobs (default: nproc)
#   O=path            - Out-of-tree build directory (default: build)
#   CMAKE_FLAGS=...   - Additional CMake flags

# ============================================================================
# Configuration
# ============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -ec

# Project metadata
VERSION := $(shell cat VERSION 2>/dev/null || echo "0.0.0")
PROJECT := loongshield

# Build directory (support out-of-tree builds like kernel's O=)
O ?= build
BUILD_DIR := $(abspath $(O))

# Source directory
SRC_DIR := $(abspath .)

# Parallel jobs (default to nproc)
JOBS ?= $(shell nproc 2>/dev/null || echo 4)

# Verbosity control (V=1 for verbose)
ifeq ($(V),1)
  Q :=
  MAKEFLAGS_QUIET :=
  CMAKE_VERBOSE := -DCMAKE_VERBOSE_MAKEFILE=ON
else
  Q := @
  MAKEFLAGS_QUIET := --no-print-directory
  CMAKE_VERBOSE :=
endif

# Colors for output (disabled if not a terminal or NO_COLOR set)
ifneq ($(NO_COLOR),)
  CLR_RESET :=
  CLR_GREEN :=
  CLR_YELLOW :=
  CLR_BLUE :=
  CLR_RED :=
  CLR_BOLD :=
else
  CLR_RESET := $(shell tput sgr0 2>/dev/null)
  CLR_GREEN := $(shell tput setaf 2 2>/dev/null)
  CLR_YELLOW := $(shell tput setaf 3 2>/dev/null)
  CLR_BLUE := $(shell tput setaf 4 2>/dev/null)
  CLR_RED := $(shell tput setaf 1 2>/dev/null)
  CLR_BOLD := $(shell tput bold 2>/dev/null)
endif

# Progress message helpers
define msg-info
	@printf "$(CLR_GREEN)==>$(CLR_RESET) $(CLR_BOLD)%s$(CLR_RESET)\n" "$(1)"
endef

define msg-warn
	@printf "$(CLR_YELLOW)==>$(CLR_RESET) $(CLR_BOLD)%s$(CLR_RESET)\n" "$(1)"
endef

define msg-stage
	@printf "$(CLR_BLUE)>>>$(CLR_RESET) %s\n" "$(1)"
endef

define msg-help-section
	@printf "$(CLR_GREEN)%s$(CLR_RESET)\n" "$(1)"
endef

define msg-help-item
	@printf "  %-22s %s\n" "$(1)" "$(2)"
endef

# CMake configuration marker
CMAKE_CACHE := $(BUILD_DIR)/CMakeCache.txt
CMAKE_MAKEFILE := $(BUILD_DIR)/CMakeFiles/Makefile.cmake
CMAKE_INPUTS := CMakeLists.txt deps/CMakeLists.txt src/CMakeLists.txt src/daemon/CMakeLists.txt

# Additional CMake flags from user
CMAKE_FLAGS ?=

# ============================================================================
# Main Targets
# ============================================================================

.PHONY: all bootstrap configure build daemon loonjit test test-unit test-integration \
        test-e2e test-quick kmod kmod-clean \
        rpm rpm-tarball rpm-srpm rpm-in-docker rpm-clean rpm-install install uninstall \
        buildreqs \
        docker docker-dev docker-run-dev \
        docker-clean clean distclean mrproper submodules deps info help reconfigure check

# Default target
all: build

# One-shot local bootstrap for development environments.
# Installs local build dependencies, initializes submodules, then builds.
bootstrap:
	$(call msg-info,Bootstrapping local development environment)
	$(call msg-stage,Installing build requirements...)
	$(Q)$(MAKE) $(MAKEFLAGS_QUIET) buildreqs
	$(call msg-stage,Initializing git submodules...)
	$(Q)$(MAKE) $(MAKEFLAGS_QUIET) submodules
	$(call msg-stage,Building project...)
	$(Q)$(MAKE) $(MAKEFLAGS_QUIET) build
	$(call msg-info,Bootstrap complete!)

# Build everything (main target)
build: configure
	$(call msg-info,Building $(PROJECT) v$(VERSION))
	$(call msg-stage,Compiling with $(JOBS) parallel jobs...)
	$(Q)$(MAKE) $(MAKEFLAGS_QUIET) -C $(BUILD_DIR) -j$(JOBS)
	$(call msg-info,Build complete!)

# Individual binaries
daemon: configure
	$(call msg-info,Building loongshield daemon)
	$(Q)$(MAKE) $(MAKEFLAGS_QUIET) -C $(BUILD_DIR) -j$(JOBS) loongshield

loonjit: configure
	$(call msg-info,Building loonjit runtime)
	$(Q)$(MAKE) $(MAKEFLAGS_QUIET) -C $(BUILD_DIR) -j$(JOBS) loonjit

# ============================================================================
# CMake Configuration (cached)
# ============================================================================

# Configure CMake and auto-reset stale caches if the source path changed.
# Note: submodules is an order-only prerequisite (after |) to avoid race conditions
configure: | submodules
	$(call msg-info,Configuring build system)
	$(Q)mkdir -p $(BUILD_DIR)
	$(Q)needs_configure=0; \
	stale_build_dir=0; \
	if [ -f $(CMAKE_CACHE) ]; then \
		cache_src=$$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' $(CMAKE_CACHE)); \
		if [ "$$cache_src" != "$(abspath $(SRC_DIR))" ]; then \
			printf "$(CLR_YELLOW)==>$(CLR_RESET) $(CLR_BOLD)%s$(CLR_RESET)\n" "Detected stale CMake cache from $$cache_src; rebuilding $(BUILD_DIR)"; \
			stale_build_dir=1; \
		fi; \
	else \
		needs_configure=1; \
	fi; \
	if [ "$$stale_build_dir" -eq 0 ] && [ -f $(CMAKE_MAKEFILE) ]; then \
		if ! grep -Fq "$(abspath $(SRC_DIR))/CMakeLists.txt" $(CMAKE_MAKEFILE); then \
			printf "$(CLR_YELLOW)==>$(CLR_RESET) $(CLR_BOLD)%s$(CLR_RESET)\n" "Detected stale generated makefiles; rebuilding $(BUILD_DIR)"; \
			stale_build_dir=1; \
		fi; \
	fi; \
	if [ "$$stale_build_dir" -eq 1 ]; then \
		rm -rf $(BUILD_DIR); \
		mkdir -p $(BUILD_DIR); \
		needs_configure=1; \
	fi; \
	if [ "$$needs_configure" -eq 0 ]; then \
		for input in $(CMAKE_INPUTS); do \
			if [ "$$input" -nt "$(CMAKE_CACHE)" ]; then \
				needs_configure=1; \
				break; \
			fi; \
		done; \
	fi; \
	if [ "$$needs_configure" -eq 1 ]; then \
		printf "$(CLR_BLUE)>>>$(CLR_RESET) %s\n" "Running CMake..."; \
		cd $(BUILD_DIR) && cmake $(CMAKE_VERBOSE) $(CMAKE_FLAGS) $(SRC_DIR); \
		printf "$(CLR_GREEN)==>$(CLR_RESET) $(CLR_BOLD)%s$(CLR_RESET)\n" "Configuration complete"; \
	else \
		printf "$(CLR_GREEN)==>$(CLR_RESET) $(CLR_BOLD)%s$(CLR_RESET)\n" "Configuration already up to date"; \
	fi

# Force reconfigure
reconfigure:
	$(call msg-warn,Forcing reconfiguration)
	$(Q)rm -f $(CMAKE_CACHE)
	$(Q)$(MAKE) $(MAKEFLAGS_QUIET) configure

# ============================================================================
# Testing
# ============================================================================

test: build
	$(call msg-info,Running test suite)
	$(Q)$(BUILD_DIR)/src/daemon/loonjit $(SRC_DIR)/tests/run.lua --type all

test-unit: build
	$(call msg-info,Running unit test suite)
	$(Q)$(BUILD_DIR)/src/daemon/loonjit $(SRC_DIR)/tests/run.lua --type unit

test-integration: build
	$(call msg-info,Running integration test suite)
	$(Q)$(BUILD_DIR)/src/daemon/loonjit $(SRC_DIR)/tests/run.lua --type integration

test-e2e: build
	$(call msg-info,Running e2e test suite)
	$(Q)$(BUILD_DIR)/src/daemon/loonjit $(SRC_DIR)/tests/run.lua --type e2e

# Quick test (assume already built)
test-quick:
	$(call msg-info,Running test suite (quick mode))
	$(Q)$(BUILD_DIR)/src/daemon/loonjit $(SRC_DIR)/tests/run.lua --type all

check: test

# ============================================================================
# Kernel Module
# ============================================================================

KMOD_DIR := $(SRC_DIR)/src/kmod
KMOD_NAME := sysmon

kmod:
	$(call msg-info,Building kernel module ($(KMOD_NAME)))
	$(Q)$(MAKE) $(MAKEFLAGS_QUIET) -C $(KMOD_DIR)

kmod-clean:
	$(call msg-info,Cleaning kernel module)
	$(Q)$(MAKE) $(MAKEFLAGS_QUIET) -C $(KMOD_DIR) clean

# ============================================================================
# Docker
# ============================================================================

DOCKER_SERVER_API_VERSION := $(shell docker version --format '{{.Server.APIVersion}}' 2>/dev/null)
DOCKER_API_ENV := $(if $(strip $(DOCKER_SERVER_API_VERSION)),DOCKER_API_VERSION=$(DOCKER_SERVER_API_VERSION))

docker: docker-dev

docker-dev: submodules
	$(call msg-info,Building development Docker image)
	$(Q)$(DOCKER_API_ENV) docker build \
		--network host \
		--build-arg CONTAINER_USER=$$(if [ $$(id -u) -eq 0 ]; then echo root; else echo developer; fi) \
		--build-arg USER_UID=$$(id -u) \
		--build-arg USER_GID=$$(id -g) \
		-t loongshield-dev:latest \
		-f Dockerfile \
		.

docker-run-dev: docker-dev
	$(call msg-info,Starting development container)
	$(Q)$(DOCKER_API_ENV) docker run --rm -it \
		--privileged \
		--network host \
		-e TERM=$${TERM:-xterm-256color} \
		-e MAKEFLAGS=-j$$(nproc) \
		-w /workspace \
		-v $(SRC_DIR):/workspace:cached \
		-v /workspace/build-docker \
		loongshield-dev:latest \
		/bin/bash

docker-clean:
	$(call msg-info,Removing Docker images)
	$(Q)docker rmi loongshield-dev:latest 2>/dev/null || true

# ============================================================================
# RPM Packaging
# ============================================================================

RPM_SPEC := $(SRC_DIR)/dist/loongshield.spec
RPM_TARBALL := $(SRC_DIR)/dist/$(PROJECT)-$(VERSION).tar.gz
RPM_BUILD_ROOT := $(BUILD_DIR)/rpmbuild
RPM_STAGING := $(BUILD_DIR)/rpm-staging
RPM_TMPDIR := $(RPM_BUILD_ROOT)/tmp
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
	NetworkManager-libnm-devel \
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
RPM_DEFINES := \
	--define "_topdir $(RPM_BUILD_ROOT)" \
	--define "_tmppath $(RPM_TMPDIR)" \
	--define "pkg_version $(VERSION)"

rpm: rpm-tarball
	$(call msg-info,Building RPM package)
	$(call msg-stage,Setting up rpmbuild tree...)
	$(Q)mkdir -p $(RPM_BUILD_ROOT)/{BUILD,RPMS,SOURCES,SPECS,SRPMS} $(RPM_TMPDIR)
	$(Q)cp $(RPM_TARBALL) $(RPM_BUILD_ROOT)/SOURCES/
	$(Q)cp $(RPM_SPEC) $(RPM_BUILD_ROOT)/SPECS/
	$(call msg-stage,Building RPM...)
	$(Q)rpmbuild -bb $(RPM_DEFINES) $(RPM_BUILD_ROOT)/SPECS/loongshield.spec
	$(call msg-info,RPM built: $(RPM_BUILD_ROOT)/RPMS/)

# Create source tarball with submodules using git archive
# This is the standard, portable way to create release tarballs
rpm-tarball: submodules
	$(call msg-info,Creating source tarball)
	$(Q)mkdir -p $(dir $(RPM_TARBALL)) $(RPM_STAGING)
	$(Q)rm -rf $(RPM_STAGING)/$(PROJECT)-$(VERSION)
	$(call msg-stage,Exporting main repository...)
	$(Q)git archive --format=tar --prefix=$(PROJECT)-$(VERSION)/ HEAD | \
		tar -C $(RPM_STAGING) -xf -
	$(call msg-stage,Exporting submodules...)
	$(Q)git submodule foreach --quiet --recursive \
		'git archive --format=tar --prefix=$(PROJECT)-$(VERSION)/$$displaypath/ HEAD | \
		tar -C $(RPM_STAGING) -xf -'
	$(call msg-stage,Creating tarball...)
	$(Q)tar -C $(RPM_STAGING) -czf $(RPM_TARBALL) $(PROJECT)-$(VERSION)
	$(Q)rm -rf $(RPM_STAGING)
	$(call msg-info,Created: $(RPM_TARBALL))

rpm-srpm: rpm-tarball
	$(call msg-info,Building source RPM)
	$(Q)mkdir -p $(RPM_BUILD_ROOT)/{BUILD,RPMS,SOURCES,SPECS,SRPMS} $(RPM_TMPDIR)
	$(Q)cp $(RPM_TARBALL) $(RPM_BUILD_ROOT)/SOURCES/
	$(Q)cp $(RPM_SPEC) $(RPM_BUILD_ROOT)/SPECS/
	$(Q)rpmbuild -bs $(RPM_DEFINES) $(RPM_BUILD_ROOT)/SPECS/loongshield.spec
	$(call msg-info,SRPM built: $(RPM_BUILD_ROOT)/SRPMS/)

rpm-clean:
	$(call msg-info,Cleaning RPM build artifacts)
	$(Q)rm -rf $(RPM_BUILD_ROOT) $(RPM_STAGING)
	$(Q)rm -f $(RPM_TARBALL)

# Install binaries and configs directly (no rpmbuild required).
# Mirrors the file layout in the RPM spec. Requires root / sudo.
DESTDIR    ?=
PREFIX     ?= /usr
SBINDIR    ?= $(PREFIX)/sbin
SYSCONFDIR ?= /etc
LICENSEDIR ?= $(PREFIX)/share/licenses

install: build
	$(call msg-info,Installing $(PROJECT) v$(VERSION))
	$(call msg-stage,Installing binaries to $(DESTDIR)$(SBINDIR)/)
	$(Q)install -d -m 0755 $(DESTDIR)$(SBINDIR)
	$(Q)install -m 0755 $(BUILD_DIR)/src/daemon/loongshield $(DESTDIR)$(SBINDIR)/loongshield
	$(Q)install -m 0755 $(BUILD_DIR)/src/daemon/loonjit     $(DESTDIR)$(SBINDIR)/loonjit
	$(call msg-stage,Installing profiles to $(DESTDIR)$(SYSCONFDIR)/loongshield/seharden/)
	$(Q)install -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/loongshield/seharden
	$(Q)install -m 0644 $(SRC_DIR)/profiles/seharden/*.yml \
		$(DESTDIR)$(SYSCONFDIR)/loongshield/seharden/
	$(call msg-stage,Installing license to $(DESTDIR)$(LICENSEDIR)/$(PROJECT)/)
	$(Q)install -d -m 0755 $(DESTDIR)$(LICENSEDIR)/$(PROJECT)
	$(Q)install -m 0644 $(SRC_DIR)/LICENSE $(DESTDIR)$(LICENSEDIR)/$(PROJECT)/LICENSE
	$(call msg-info,Installation complete)

# Remove installed files from the system
uninstall:
	$(call msg-info,Uninstalling $(PROJECT))
	$(Q)rm -f  $(DESTDIR)$(SBINDIR)/loongshield $(DESTDIR)$(SBINDIR)/loonjit
	$(Q)rm -rf $(DESTDIR)$(SYSCONFDIR)/loongshield
	$(Q)rm -rf $(DESTDIR)$(LICENSEDIR)/$(PROJECT)
	$(call msg-info,Uninstalled)

# Build RPM and install it via rpm -Uvh (requires rpmbuild)
rpm-install: rpm
	$(call msg-info,Installing RPM for $(PROJECT) v$(VERSION))
	$(Q)RPM_FILE=$$(find $(RPM_BUILD_ROOT)/RPMS -name "$(PROJECT)-$(VERSION)-*.rpm" | head -1); \
	if [ -z "$$RPM_FILE" ]; then \
		echo "Error: RPM not found under $(RPM_BUILD_ROOT)/RPMS/"; \
		exit 1; \
	fi; \
	echo "==> Installing $$RPM_FILE"; \
	rpm -Uvh "$$RPM_FILE"
	$(call msg-info,Installation complete)

# Install local build dependencies on CentOS/RHEL/Anolis-like systems.
# Uses dnf when available, falls back to yum.
buildreqs:
	$(call msg-info,Installing CentOS-like build dependencies)
	$(Q)PKG_MGR=$$(command -v dnf || command -v yum || true); \
	if [ -z "$$PKG_MGR" ]; then \
		echo "Error: neither dnf nor yum was found on this system."; \
		exit 1; \
	fi; \
	SUDO=""; \
	if [ "$$(id -u)" -ne 0 ]; then \
		SUDO=sudo; \
	fi; \
	echo "==> Using package manager: $$PKG_MGR"; \
	$$SUDO $$PKG_MGR install -y $(RPM_BUILD_REQUIRES)

# Build RPM in the CentOS development container
rpm-in-docker: docker-dev rpm-tarball
	$(call msg-info,Building RPM in Docker container)
	$(call msg-stage,Preparing build environment...)
	$(Q)mkdir -p $(BUILD_DIR)/rpmbuild-docker
	$(Q)$(DOCKER_API_ENV) docker run --rm \
		--network host \
		--user 0:0 \
		-v $(SRC_DIR):/workspace:ro \
		-v $(BUILD_DIR)/rpmbuild-docker:/root/rpmbuild \
		-w /root \
		loongshield-dev:latest \
		/bin/bash -lc '\
			set -e; \
			echo "==> Setting up rpmbuild tree..."; \
			mkdir -p ~/rpmbuild/tmp; \
			rpmdev-setuptree; \
			cp /workspace/dist/$(PROJECT)-$(VERSION).tar.gz ~/rpmbuild/SOURCES/; \
			cp /workspace/dist/loongshield.spec ~/rpmbuild/SPECS/; \
			echo "==> Building RPM..."; \
			rpmbuild -bb \
				--define "_tmppath %{getenv:HOME}/rpmbuild/tmp" \
				--define "pkg_version $(VERSION)" \
				~/rpmbuild/SPECS/loongshield.spec; \
			echo "==> Build complete!"; \
			ls -la ~/rpmbuild/RPMS/*/ \
		'
	$(call msg-info,RPM packages available at: $(BUILD_DIR)/rpmbuild-docker/RPMS/)

# ============================================================================
# Submodules and Dependencies
# ============================================================================

SUBMODULE_SENTINELS := \
	deps/luajit/luajit/src/lua.h \
	deps/libuv/libuv/src/unix/async.c \
	deps/lpeg/lpeg/lpcap.c \
	deps/lua-openssl/lua-auxiliar/auxiliar.c \
	deps/lua-openssl/lua-openssl/src/openssl.c \
	deps/libcap/libcap/libcap/cap_alloc.c

submodules:
	$(Q)missing_submodules=0; \
	for sentinel in $(SUBMODULE_SENTINELS); do \
		if [ ! -f "$$sentinel" ]; then \
			missing_submodules=1; \
			break; \
		fi; \
	done; \
	if [ "$$missing_submodules" -eq 1 ]; then \
		printf "$(CLR_GREEN)==>$(CLR_RESET) $(CLR_BOLD)%s$(CLR_RESET)\n" "Initializing git submodules"; \
		git submodule update --init --recursive; \
	fi; \
	for sentinel in $(SUBMODULE_SENTINELS); do \
		if [ ! -f "$$sentinel" ]; then \
			printf "$(CLR_RED)error:$(CLR_RESET) required vendored source is missing: %s\n" "$$sentinel" >&2; \
			exit 1; \
		fi; \
	done

deps: submodules configure
	$(call msg-info,Building dependencies only)
	$(Q)$(MAKE) $(MAKEFLAGS_QUIET) -C $(BUILD_DIR) -j$(JOBS) libluajit libuv luv

# ============================================================================
# Cleaning
# ============================================================================

clean:
	$(call msg-info,Cleaning build artifacts)
	$(Q)if [ -d $(BUILD_DIR) ]; then \
		$(MAKE) $(MAKEFLAGS_QUIET) -C $(BUILD_DIR) clean 2>/dev/null || true; \
	fi
	$(Q)rm -f src/daemon/bin_ramfs_luac.h src/daemon/bin_initrd_tar.h

# Deep clean (remove build directory entirely)
distclean: clean kmod-clean
	$(call msg-info,Removing build directory)
	$(Q)rm -rf $(BUILD_DIR)
	$(Q)rm -f dist/$(PROJECT)-*.tar.gz

# Clean everything including submodules (rarely needed)
mrproper: distclean
	$(call msg-warn,Deep cleaning (including submodules))
	$(Q)git submodule deinit -f --all 2>/dev/null || true

# ============================================================================
# Information and Help
# ============================================================================

info:
	@echo "$(CLR_BOLD)Loongshield Build Information$(CLR_RESET)"
	@echo "=============================="
	@echo "Version:      $(VERSION)"
	@echo "Source Dir:   $(SRC_DIR)"
	@echo "Build Dir:    $(BUILD_DIR)"
	@echo "Parallel:     $(JOBS) jobs"
	@echo "CMake Cache:  $(if $(wildcard $(CMAKE_CACHE)),exists,not configured)"

help:
	@echo "$(CLR_BOLD)Loongshield Build System$(CLR_RESET)"
	@echo "========================"
	@echo ""
	$(call msg-help-section,Main Targets:)
	$(call msg-help-item,make,Build everything (daemon + loonjit))
	$(call msg-help-item,make bootstrap,Install build deps and init submodules before building)
	$(call msg-help-item,make configure,Configure the CMake build tree)
	$(call msg-help-item,make reconfigure,Force a fresh CMake reconfiguration)
	$(call msg-help-item,make daemon,Build only loongshield daemon)
	$(call msg-help-item,make loonjit,Build only loonjit runtime)
	@echo ""
	$(call msg-help-section,Testing:)
	$(call msg-help-item,make test,Build and run all test suites)
	$(call msg-help-item,make test-unit,Run unit test suite)
	$(call msg-help-item,make test-integration,Run integration test suite)
	$(call msg-help-item,make test-e2e,Run e2e test suite)
	$(call msg-help-item,make test-quick,Run all tests without rebuilding)
	$(call msg-help-item,make check,Alias for make test)
	@echo ""
	$(call msg-help-section,Kernel Module:)
	$(call msg-help-item,make kmod,Build sysmon kernel module)
	$(call msg-help-item,make kmod-clean,Clean kernel module build)
	@echo ""
	$(call msg-help-section,Docker:)
	$(call msg-help-item,make docker,Build the CentOS development image)
	$(call msg-help-item,make docker-dev,Build development image only)
	$(call msg-help-item,make docker-run-dev,Start development container)
	$(call msg-help-item,make docker-clean,Remove Docker images)
	@echo ""
	$(call msg-help-section,Installation:)
	$(call msg-help-item,make install,Build and install binaries plus profiles)
	$(call msg-help-item,make uninstall,Remove installed files from system)
	$(call msg-help-item,make rpm-install,Build RPM then install via rpm -Uvh)
	$(call msg-help-item,make buildreqs,Install build deps on CentOS-like systems)
	@echo ""
	$(call msg-help-section,RPM Packaging:)
	$(call msg-help-item,make rpm,Build RPM package locally)
	$(call msg-help-item,make rpm-srpm,Build source RPM)
	$(call msg-help-item,make rpm-tarball,Create source tarball only)
	$(call msg-help-item,make rpm-in-docker,Build RPM in the Docker development image)
	$(call msg-help-item,make rpm-clean,Clean RPM build artifacts)
	@echo ""
	$(call msg-help-section,Maintenance:)
	$(call msg-help-item,make clean,Clean build artifacts)
	$(call msg-help-item,make distclean,Remove build directory entirely)
	$(call msg-help-item,make mrproper,Deep clean including submodule state)
	$(call msg-help-item,make submodules,Initialize git submodules)
	$(call msg-help-item,make deps,Build bundled dependencies only)
	$(call msg-help-item,make info,Show build configuration)
	$(call msg-help-item,make help,Show this help message)
	@echo ""
	$(call msg-help-section,Variables:)
	$(call msg-help-item,V=1,Enable verbose output)
	$(call msg-help-item,JOBS=N,Set parallel jobs (default: $(JOBS)))
	$(call msg-help-item,O=path,Set build directory (default: build))
	$(call msg-help-item,CMAKE_FLAGS=...,Pass additional flags to CMake)
	$(call msg-help-item,NO_COLOR=1,Disable colored output)
	@echo ""
	$(call msg-help-section,Examples:)
	$(call msg-help-item,make bootstrap,Prepare a fresh local dev environment)
	$(call msg-help-item,make V=1 JOBS=8,Verbose build with 8 jobs)
	$(call msg-help-item,make O=build-debug,Build in a custom directory)
	$(call msg-help-item,make test-quick,Run tests without rebuilding)
	$(call msg-help-item,CMAKE_FLAGS=-DCMAKE_BUILD_TYPE=Release make rpm,Build a release RPM)
