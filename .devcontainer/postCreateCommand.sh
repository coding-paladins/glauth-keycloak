#!/bin/bash

# Copy SSH keys if mounted and fix permissions
if [ -d /tmp/host-ssh ]; then
    mkdir -p ~/.ssh
    # Copy entire SSH directory structure recursively
    sudo cp -r /tmp/host-ssh/. ~/.ssh/
    # Change ownership to current user
    sudo chown -R $(whoami):$(whoami) ~/.ssh
    # Set proper permissions
    chmod 700 ~/.ssh
    # Set permissions for private keys
    find ~/.ssh -type f -name "id_*" ! -name "*.pub" -exec chmod 600 {} \; 2>/dev/null || true
    # Set permissions for public keys
    find ~/.ssh -type f -name "*.pub" -exec chmod 644 {} \; 2>/dev/null || true
    # Set permissions for known_hosts and config
    [ -f ~/.ssh/known_hosts ] && chmod 644 ~/.ssh/known_hosts
    [ -f ~/.ssh/config ] && chmod 644 ~/.ssh/config
fi

# Preserve existing user identity
USER_NAME=$(git config --global user.name 2>/dev/null || echo "")
USER_EMAIL=$(git config --global user.email 2>/dev/null || echo "")

# Clean Git configuration
rm -f ~/.gitconfig

# Set up minimal Git configuration
git config --global user.name "$USER_NAME"
git config --global user.email "$USER_EMAIL"
git config --global core.editor vim
git config --global --add safe.directory /workspace
git config --global --add safe.directory '*'

# Install Python package in editable mode
pip install -e .
