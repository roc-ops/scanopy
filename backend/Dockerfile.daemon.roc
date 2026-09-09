# The daemon image the RocContLab pilot runs. A FORK-ONLY file: upstream's
# backend/Dockerfile.daemon is deliberately left untouched so it keeps merging cleanly, and this
# sits beside it rather than diverging it.
#
# It exists because the recipe used to live only in prose and in `docker history`. Rebuilding the
# pilot on 2026-09-09 meant reconstructing this file from the layers of the running image, which
# is archaeology no one should have to repeat -- and archaeology that silently loses a deviation
# the day someone reads the wrong layer.
#
# Exactly two deviations from upstream, both load-bearing:
#
#   1. ubuntu:24.04 rather than debian:bookworm-slim. The daemon is built on netlab-server against
#      its glibc; on bookworm-slim the binary aborts at start with a GLIBC_2.39 not-found. Any
#      base whose glibc is at least the build host's would do -- 24.04 is the one that is proven.
#   2. the `lldpd` package, for `lldpcli`. The lldpd collector (scanopy#689, PR scanopy#697) reads
#      the LOCAL lldpd over its control socket so a daemon host contributes its own L2 view; with
#      no `lldpcli` in the image that collector finds nothing and says so quietly.
#
# Build it the way docs/scanopy-fork.md records, from a context holding the release binary:
#
#   cargo build --release --bin daemon
#   mkdir -p /tmp/daemon-ctx && cp target/release/daemon /tmp/daemon-ctx/scanopy-daemon-linux-amd64
#   cp backend/Dockerfile.daemon.roc /tmp/daemon-ctx/
#   docker build -f /tmp/daemon-ctx/Dockerfile.daemon.roc -t roccontlab/scanopy-daemon:<tag> /tmp/daemon-ctx
#
# /tmp is tmpfs on that box, so the context does not survive a reboot. This file does.

FROM ubuntu:24.04

ARG TARGETARCH

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    iproute2 \
    iputils-ping \
    net-tools \
    procps \
    tcpdump \
    lldpd \
    && rm -rf /var/lib/apt/lists/*

# Pre-built binary copied in during build (named by architecture)
COPY scanopy-daemon-linux-${TARGETARCH} /usr/local/bin/scanopy-daemon
RUN chmod +x /usr/local/bin/scanopy-daemon

LABEL org.opencontainers.image.title="Scanopy Daemon" \
      org.opencontainers.image.description="Scanopy daemon — network discovery agent." \
      org.opencontainers.image.url="https://github.com/scanopy/scanopy" \
      org.opencontainers.image.source="https://github.com/scanopy/scanopy" \
      org.opencontainers.image.documentation="https://github.com/scanopy/scanopy#readme" \
      org.opencontainers.image.vendor="Scanopy" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

EXPOSE 60073

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:60073/api/health || exit 1

CMD ["scanopy-daemon"]
