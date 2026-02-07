#!/usr/bin/env bash
# Run LDAP feature tests against an already-reachable GLAuth server.
# Start port-forward in another terminal, then run this script. For example:
#
#   export KUBECONFIG=/workspaces/glauth-keycloak/kubeconfig
#   kubectl port-forward -n security pod/glauth-59b9676cdc-ns5hp 3893:3893
#
# If port 3893 is already in use, use another local port and set LDAP_URL:
#
#   kubectl port-forward -n security pod/glauth-59b9676cdc-ns5hp 3894:3893
#   LDAP_URL=ldap://127.0.0.1:3894 ./scripts/port-forward-and-test.sh
#
# Set LDAP_URL, LDAP_BASE_DN or LDAP_DOMAIN, LDAP_USER, LDAP_PASSWORD as needed.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export LDAP_URL="${LDAP_URL:-ldap://127.0.0.1:3893}"
export LDAP_USER="${LDAP_USER:-test}"
export LDAP_PASSWORD="${LDAP_PASSWORD:-test}"

if [[ -z "${LDAP_BASE_DN}" ]] && [[ -z "${LDAP_DOMAIN}" ]]; then
  export LDAP_BASE_DN="${LDAP_BASE_DN:-dc=societycell,dc=local}"
  echo "using default base DN: $LDAP_BASE_DN (set LDAP_BASE_DN or LDAP_DOMAIN to override)"
fi

echo "running LDAP tests (user: $LDAP_USER, url: $LDAP_URL)..."
(cd "$REPO_ROOT" && go run ./cmd/test-ldap/)
echo "done."
