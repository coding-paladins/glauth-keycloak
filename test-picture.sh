#!/bin/bash
# Test LDAP picture attribute with port-forward to GLAuth

set -e

echo "=== GLAuth-Keycloak Picture Attribute Test ==="
echo

# Get Keycloak configuration
echo "Getting configuration from secret..."
KEYCLOAK_REALM=$(kubectl get secret glauth -n security -o jsonpath='{.data.KEYCLOAK_REALM}' | base64 -d)
LDAP_CLIENT_ID=$(kubectl get secret glauth -n security -o jsonpath='{.data.KEYCLOAK_LDAP_CLIENT_ID}' | base64 -d)
LDAP_CLIENT_SECRET=$(kubectl get secret glauth -n security -o jsonpath='{.data.KEYCLOAK_LDAP_CLIENT_SECRET}' | base64 -d)
LDAP_DOMAIN=$(kubectl get secret glauth -n security -o jsonpath='{.data.LDAP_DOMAIN}' | base64 -d)

echo "Realm: $KEYCLOAK_REALM"
echo "Client ID: $LDAP_CLIENT_ID"
echo "LDAP Domain: $LDAP_DOMAIN"
echo

# Start port-forward in background
echo "Starting port-forward to GLAuth (port 3893)..."
kubectl port-forward -n security svc/glauth 3893:3893 >/dev/null 2>&1 &
PF_PID=$!

# Give port-forward time to establish
sleep 2

# Cleanup function
cleanup() {
    echo
    echo "Stopping port-forward..."
    kill $PF_PID 2>/dev/null || true
}
trap cleanup EXIT

# Test LDAP bind and search
echo "Testing LDAP connection..."
LDAP_BIND_DN="cn=$LDAP_CLIENT_ID,cn=bind,dc=${LDAP_DOMAIN//.*/},dc=${LDAP_DOMAIN/*./}" \
LDAP_BIND_PW="$LDAP_CLIENT_SECRET" \
LDAP_BASE_DN="dc=${LDAP_DOMAIN//.*/},dc=${LDAP_DOMAIN/*./}" \
go run ./cmd/verify-ldap-picture

echo
echo "=== Test complete ==="
