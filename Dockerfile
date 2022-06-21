FROM debian:bullseye-slim as builder

# Set this to the current release version: it gets done so as part of the release.
ARG RELEASE_VERSION=1.9.5

ARG FLB_NIGHTLY_BUILD
ENV FLB_NIGHTLY_BUILD=$FLB_NIGHTLY_BUILD

RUN mkdir -p /fluent-bit/bin /fluent-bit/etc /fluent-bit/log

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    cmake \
    git \
    make \
    tar \
    wget \
    libssl-dev \
    libsasl2-dev \
    pkg-config \
    libunwind-dev \
    libbrotli-dev \
    brotli \
    libzstd-dev \
    libsystemd-dev \
    zlib1g-dev \
    libpq-dev \
    postgresql-server-dev-all \
    zstd \
    flex \
    bison \
    libyaml-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ARG LIBZMQ_VERSION=4.3.4
RUN wget https://github.com/zeromq/libzmq/releases/download/v${LIBZMQ_VERSION}/zeromq-${LIBZMQ_VERSION}.tar.gz -O /tmp/libzmq.tar.gz && \
    tar -xzf /tmp/libzmq.tar.gz -C /tmp/ && \
    cd /tmp/zeromq-${LIBZMQ_VERSION} && \
    ./configure && make && make install

ARG LIBCZMQ_VERSION=4.2.1
RUN wget https://github.com/zeromq/czmq/releases/download/v${LIBCZMQ_VERSION}/czmq-${LIBCZMQ_VERSION}.tar.gz -O /tmp/czmq.tar.gz && \
    tar -xzf /tmp/czmq.tar.gz -C /tmp/ && \
    ls -la /tmp && \
    cd /tmp/czmq-${LIBCZMQ_VERSION} && \
    ./configure && make && make install

ARG MIMALLOC_VERSION=2.0.6
RUN git clone --depth=1 -b v${MIMALLOC_VERSION} https://github.com/microsoft/mimalloc /tmp/mimalloc && \
    cd /tmp/mimalloc && mkdir -p out/release && cd out/release && \
    cmake ../.. && make && make install

RUN ls -la /usr/local/include && ls -la /usr/local/lib/ && nm /usr/local/lib/libczmq.so

# Must be run from root of repo
WORKDIR /src/fluent-bit/
COPY . ./

WORKDIR /src/fluent-bit/build/
RUN cmake -DFLB_RELEASE=On \
          -DFLB_TRACE=Off \
          -DFLB_JEMALLOC=On \
          -DFLB_TLS=On \
          -DFLB_SHARED_LIB=Off \
          -DFLB_EXAMPLES=Off \
          -DFLB_HTTP_SERVER=On \
          -DFLB_IN_EXEC=Off \
          -DFLB_IN_SYSTEMD=On \
          -DFLB_OUT_KAFKA=On \
          -DFLB_OUT_PGSQL=On \
          -DFLB_NIGHTLY_BUILD="$FLB_NIGHTLY_BUILD" \
          -DFLB_LOG_NO_CONTROL_CHARS=On \
          ..

RUN make -j $(getconf _NPROCESSORS_ONLN)
RUN install bin/fluent-bit /fluent-bit/bin/

# Configuration files
COPY conf/fluent-bit.conf \
     conf/parsers.conf \
     conf/parsers_java.conf \
     conf/parsers_extra.conf \
     conf/parsers_openstack.conf \
     conf/parsers_cinder.conf \
     conf/plugins.conf \
     /fluent-bit/etc/

# Simple example of how to properly extract packages for reuse in distroless
# Taken from: https://github.com/GoogleContainerTools/distroless/issues/863
FROM debian:bullseye-slim as deb-extractor

# We download all debs locally then extract them into a directory we can use as the root for distroless.
# We also include some extra handling for the status files that some tooling uses for scanning, etc.
WORKDIR /tmp
RUN apt-get update && \
    apt-get download \
        libssl1.1 \
        libsasl2-2 \
        pkg-config \
        libpq5 \
        libsystemd0 \
        zlib1g \
        ca-certificates \
        libatomic1 \
        libgcrypt20 \
        libzstd1 \
        liblz4-1 \
        libgssapi-krb5-2 \
        libldap-2.4-2 \
        libgpg-error0 \
        libkrb5-3 \
        libk5crypto3 \
        libcom-err2 \
        libkrb5support0 \
        libgnutls30 \
        libkeyutils1 \
        libp11-kit0 \
        libidn2-0 \
        libunistring2 \
        libtasn1-6 \
        libnettle8 \
        libhogweed6 \
        libgmp10 \
        libffi7 \
        liblzma5 \
        libyaml-0-2 \
        libbrotli1 \
        brotli \
        libzstd1 \
        zstd \
        libunwind8 \
        liblz4-1  && \
    mkdir -p /dpkg/var/lib/dpkg/status.d/ && \
    for deb in *.deb; do \
        package_name=$(dpkg-deb -I ${deb} | awk '/^ Package: .*$/ {print $2}'); \
        echo "Processing: ${package_name}"; \
        dpkg --ctrl-tarfile $deb | tar -Oxf - ./control > /dpkg/var/lib/dpkg/status.d/${package_name}; \
        dpkg --extract $deb /dpkg || exit 10; \
    done

# Remove unnecessary files extracted from deb packages like man pages and docs etc.
RUN find /dpkg/ -type d -empty -delete && \
    rm -r /dpkg/usr/share/doc/

# We want latest at time of build
# hadolint ignore=DL3006
FROM gcr.io/distroless/cc-debian11 as production
ARG RELEASE_VERSION
ENV FLUENT_BIT_VERSION=${RELEASE_VERSION}
LABEL description="Fluent Bit multi-architecture container image" \
      vendor="Fluent Organization" \
      version="${RELEASE_VERSION}" \
      author="Eduardo Silva <eduardo@calyptia.com>" \
      org.opencontainers.image.description="Fluent Bit container image" \
      org.opencontainers.image.title="Fluent Bit" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Fluent Organization" \
      org.opencontainers.image.version="${RELEASE_VERSION}" \
      org.opencontainers.image.source="https://github.com/fluent/fluent-bit" \
      org.opencontainers.image.documentation="https://docs.fluentbit.io/" \
      org.opencontainers.image.authors="Eduardo Silva <eduardo@calyptia.com>"

# Copy the libraries from the extractor stage into root
COPY --from=deb-extractor /dpkg /

# Copy certificates
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

# Finally the binaries as most likely to change
COPY --from=builder /fluent-bit /fluent-bit

EXPOSE 2020

# Entry point
ENTRYPOINT [ "/fluent-bit/bin/fluent-bit" ]
CMD ["/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf"]

FROM debian:bullseye-slim as debug
ARG RELEASE_VERSION
ENV FLUENT_BIT_VERSION=${RELEASE_VERSION}
LABEL description="Fluent Bit multi-architecture debug container image" \
      vendor="Fluent Organization" \
      version="${RELEASE_VERSION}-debug" \
      author="Eduardo Silva <eduardo@calyptia.com>" \
      org.opencontainers.image.description="Fluent Bit debug container image" \
      org.opencontainers.image.title="Fluent Bit Debug" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Fluent Organization" \
      org.opencontainers.image.version="${RELEASE_VERSION}-debug" \
      org.opencontainers.image.source="https://github.com/fluent/fluent-bit" \
      org.opencontainers.image.documentation="https://docs.fluentbit.io/" \
      org.opencontainers.image.authors="Eduardo Silva <eduardo@calyptia.com>"

ENV DEBIAN_FRONTEND noninteractive

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl1.1 \
        libsasl2-2 \
        pkg-config \
        libpq5 \
        libsystemd0 \
        zlib1g \
        ca-certificates \
        libatomic1 \
        libgcrypt20 \
        libyaml-0-2 \
        libbrotli1 \
        brotli \
        libzstd1 \
        zstd \
        libunwind8 \
        liblz4-1 \
        bash gdb valgrind build-essential  \
        git bash-completion vim tmux jq \
        dnsutils iputils-ping iputils-arping iputils-tracepath iputils-clockdiff \
        tcpdump curl nmap tcpflow iftop \
        net-tools mtr netcat-openbsd bridge-utils iperf ngrep \
        openssl \
        htop atop strace iotop sysstat ncdu logrotate hdparm pciutils psmisc tree pv \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/* /usr/local/lib/
COPY --from=builder /fluent-bit /fluent-bit

EXPOSE 2020

# No entry point so we can just shell in
CMD ["/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf"]
