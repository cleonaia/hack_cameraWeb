FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

# Install essential network security, analysis, and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    clang \
    make \
    valgrind \
    gdb \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    arping \
    dsniff \
    ethtool \
    iptables \
    curl \
    ca-certificates \
    openssl \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Keep Python packages out of Debian's system interpreter. Versions are pinned
# in the project lock file and installed only into this image-local venv.
COPY requirements.lock /tmp/requirements.lock
RUN python3 -m venv /opt/ft-malcolm-venv \
    && /opt/ft-malcolm-venv/bin/pip install --no-cache-dir -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock
ENV PATH="/opt/ft-malcolm-venv/bin:${PATH}"

WORKDIR /workspace

# Set default entrypoint
CMD ["/bin/bash"]
