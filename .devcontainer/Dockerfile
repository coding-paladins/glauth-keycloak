FROM mcr.microsoft.com/devcontainers/go:1.21

WORKDIR /workspace

# Install kubectl (remove unsigned Yarn repo from base image to avoid apt-get update failure)
RUN find /etc/apt/sources.list.d -name '*.list' -exec grep -l yarnpkg {} \; -delete 2>/dev/null || true && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    wget \
    ca-certificates \
    ldap-utils \
    && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl \
    && rm kubectl \
    && rm -rf /var/lib/apt/lists/*
