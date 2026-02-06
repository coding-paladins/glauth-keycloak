FROM mcr.microsoft.com/devcontainers/python:3-3.12-bookworm

# Remove Yarn repository to avoid expired GPG key error (we use npm via nvm instead)
RUN rm -f /etc/apt/sources.list.d/yarn.list /etc/apt/sources.list.d/yarn.list.save || true

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    vim \
    iputils-ping \
    dnsutils \
    age \
    curl \
    libnss-mdns \
    && rm -rf /var/lib/apt/lists/*

# Configure NSS to use mDNS (with host networking, this will use the host's Avahi daemon)
RUN sed -i 's/hosts:.*/hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4/' /etc/nsswitch.conf
RUN pip install --no-cache-dir \
    ansible-core==2.18.0 \
    proxmoxer \
    requests \
    pyyaml \
    ansible-lint \
    netaddr \
    kubernetes

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl \
    && rm kubectl
RUN curl -sLS https://get.k3sup.dev | sh

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip" \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/awscliv2.zip /tmp/aws

# Install Helm
RUN curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-4 \
    && chmod 700 get_helm.sh \
    && ./get_helm.sh \
    && rm get_helm.sh

# Install kubelogin for OIDC authentication
RUN KUBELOGIN_VERSION=$(curl -sL https://api.github.com/repos/int128/kubelogin/releases/latest | grep "tag_name" | cut -d '"' -f 4) \
    && curl -LO "https://github.com/int128/kubelogin/releases/download/${KUBELOGIN_VERSION}/kubelogin_linux_amd64.zip" \
    && unzip kubelogin_linux_amd64.zip \
    && install -o root -g root -m 0755 kubelogin /usr/local/bin/kubelogin \
    && ln -sf /usr/local/bin/kubelogin /usr/local/bin/kubectl-oidc_login \
    && rm kubelogin kubelogin_linux_amd64.zip LICENSE README.md

# Install virtctl for KubeVirt
RUN VIRTCTL_VERSION=$(curl -s https://storage.googleapis.com/kubevirt-prow/release/kubevirt/kubevirt/stable.txt) \
    && curl -LO "https://github.com/kubevirt/kubevirt/releases/download/${VIRTCTL_VERSION}/virtctl-${VIRTCTL_VERSION}-linux-amd64" \
    && install -o root -g root -m 0755 "virtctl-${VIRTCTL_VERSION}-linux-amd64" /usr/local/bin/virtctl \
    && rm "virtctl-${VIRTCTL_VERSION}-linux-amd64"

# Install kubectl Mayastor plugin (OpenEBS Replicated PV Mayastor: volumes, pools, replica topology)
# Use: kubectl mayastor get volumes|pools|volume-replica-topology <id>; default namespace mayastor, use -n storage if needed
# https://openebs.io/docs/user-guides/replicated-storage-user-guide/replicated-pv-mayastor/advanced-operations/kubectl-plugin
RUN MAYASTOR_PLUGIN_VERSION=$(curl -sL https://api.github.com/repos/openebs/mayastor-control-plane/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') \
    && curl -sLO "https://github.com/openebs/mayastor-control-plane/releases/download/${MAYASTOR_PLUGIN_VERSION}/kubectl-mayastor-x86_64-linux-musl.tar.gz" \
    && tar -xzf kubectl-mayastor-x86_64-linux-musl.tar.gz \
    && install -o root -g root -m 0755 kubectl-mayastor /usr/local/bin/kubectl-mayastor \
    && rm kubectl-mayastor kubectl-mayastor-x86_64-linux-musl.tar.gz

COPY ansible/requirements.yml /tmp/requirements.yml

# Install recyclarr (needs root for /usr/local/bin)
RUN wget "https://github.com/recyclarr/recyclarr/releases/latest/download/recyclarr-linux-x64.tar.xz" -O - | tar xJ --overwrite -C /usr/local/bin

# Install ansible collections and roles as root first (with retry for transient API failures)
RUN for i in 1 2 3; do \
    ansible-galaxy install -r /tmp/requirements.yml && break || \
    (echo "ansible-galaxy install attempt $i failed, retrying in 5 seconds..." && sleep 5); \
    done
# Install SOPS binary directly from GitHub (simpler than using the Ansible role)
RUN SOPS_VERSION=$(curl -s https://api.github.com/repos/getsops/sops/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') && \
    curl -LO "https://github.com/getsops/sops/releases/download/${SOPS_VERSION}/sops-${SOPS_VERSION}.linux.amd64" && \
    install -o root -g root -m 0755 "sops-${SOPS_VERSION}.linux.amd64" /usr/local/bin/sops && \
    rm "sops-${SOPS_VERSION}.linux.amd64"

# Install Go (for glauth-keycloak and other Go tooling)
RUN GO_VERSION=1.21.13 && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

USER vscode
RUN curl -s https://fluxcd.io/install.sh | bash

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash && \
    export NVM_DIR="/usr/local/share/nvm" && \
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" && \
    nvm install 22 && \
    npm install mega-linter-runner -g
