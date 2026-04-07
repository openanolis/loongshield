# Development and packaging environment for Loongshield
FROM quay.io/centos/centos:stream9

LABEL maintainer="loongshield-dev"
LABEL description="Loongshield development and packaging environment"

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Replace the default metalink-based repo config with explicit official Stream mirrors.
RUN set -eux; \
    repo_file=/etc/yum.repos.d/CentOS-Stream.repo; \
    dnf_conf=/etc/dnf/dnf.conf; \
    mkdir -p /etc/yum.repos.d/loongshield-disabled; \
    find /etc/yum.repos.d -maxdepth 1 -name '*.repo' -exec mv {} /etc/yum.repos.d/loongshield-disabled/ \; ; \
    printf '%s\n' \
        '[baseos]' \
        'name=CentOS Stream 9 - BaseOS' \
        'baseurl=https://mirror.stream.centos.org/9-stream/BaseOS/$basearch/os/' \
        'enabled=1' \
        'gpgcheck=0' \
        'repo_gpgcheck=0' \
        '' \
        '[appstream]' \
        'name=CentOS Stream 9 - AppStream' \
        'baseurl=https://mirror.stream.centos.org/9-stream/AppStream/$basearch/os/' \
        'enabled=1' \
        'gpgcheck=0' \
        'repo_gpgcheck=0' \
        '' \
        '[crb]' \
        'name=CentOS Stream 9 - CRB' \
        'baseurl=https://mirror.stream.centos.org/9-stream/CRB/$basearch/os/' \
        'enabled=1' \
        'gpgcheck=0' \
        'repo_gpgcheck=0' \
        > "$repo_file"; \
    sed -i 's/^max_parallel_downloads=.*/max_parallel_downloads=20/' "$dnf_conf"; \
    grep -q '^max_parallel_downloads=' "$dnf_conf" || \
        sed -i '/^\[main\]$/a max_parallel_downloads=20' "$dnf_conf"

RUN dnf install -y \
    git \
    cmake \
    gcc \
    gcc-c++ \
    make \
    perl \
    perl-IPC-Cmd \
    perl-FindBin \
    perl-ExtUtils-MakeMaker \
    which \
    sudo \
    glibc-langpack-en \
    rpm-build \
    rpmdevtools \
    systemd \
    NetworkManager-libnm-devel \
    audit-libs-devel \
    dbus-devel \
    elfutils-libelf-devel \
    libarchive-devel \
    libattr-devel \
    libcurl-devel \
    libmount-devel \
    libpsl-devel \
    libyaml-devel \
    libcap-devel \
    libzstd-devel \
    openssl-devel \
    rpm-devel \
    systemd-devel \
    xz-devel \
    vim \
    gdb \
    strace \
    valgrind \
    tree \
    less \
    procps-ng \
    findutils \
    diffutils \
    && dnf clean all

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8 \
    O=build-docker

# Create a non-root user for development when the host is not root.
ARG USER_UID=1000
ARG USER_GID=1000
ARG CONTAINER_USER=developer
RUN if [ "${CONTAINER_USER}" = "root" ]; then \
        echo "root ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers; \
    else \
        groupadd -g ${USER_GID} developer && \
        useradd -m -s /bin/bash -u ${USER_UID} -g ${USER_GID} developer && \
        echo "developer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers; \
    fi

# Set working directory
WORKDIR /workspace

# Change ownership to developer user
RUN if [ "${CONTAINER_USER}" = "developer" ]; then \
        chown -R developer:developer /workspace; \
    fi

# Switch to developer user
USER ${CONTAINER_USER}

# Set up git configuration helpers
RUN git config --global --add safe.directory /workspace && \
    git config --global http.postBuffer 524288000 && \
    git config --global http.maxRequestBuffer 100M && \
    git config --global core.compression 0

# Set up useful bash aliases
RUN echo 'alias ll="ls -lah"' >> ~/.bashrc && \
    echo 'alias build="cd /workspace && make O=\${O:-build} -j\$(nproc)"' >> ~/.bashrc && \
    echo 'alias test="cd /workspace && ./\${O:-build}/src/daemon/loonjit ./run_tests.lua"' >> ~/.bashrc

# Default command
CMD ["/bin/bash"]
