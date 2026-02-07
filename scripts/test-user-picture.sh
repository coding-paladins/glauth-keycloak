#!/bin/bash
# Quick test to verify a specific user's LDAP attributes including picture

USERNAME="${1:-parthenona}"
LDAP_URL="${LDAP_URL:-ldap://127.0.0.1:3893}"

if [ -z "$LDAP_BIND_DN" ] || [ -z "$LDAP_BIND_PW" ]; then
    echo "Error: Set LDAP_BIND_DN and LDAP_BIND_PW environment variables"
    echo
    echo "Quick setup:"
    echo "  export LDAP_BIND_DN=\"cn=glauth-ldap,cn=bind,dc=societycell,dc=local\""
    echo "  export LDAP_BIND_PW=\$(kubectl get secret glauth -n security -o jsonpath='{.data.KEYCLOAK_LDAP_CLIENT_SECRET}' | base64 -d)"
    echo
    echo "Then run: $0 USERNAME"
    exit 1
fi

# Use ldapsearch if available, otherwise suggest installing it
if command -v ldapsearch &> /dev/null; then
    echo "Searching for user: $USERNAME"
    echo "========================================"
    ldapsearch -x -H "$LDAP_URL" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PW" \
        -b "cn=users,dc=societycell,dc=local" \
        "(cn=$USERNAME)" \
        cn uid mail displayName jpegPhoto
else
    echo "ldapsearch not found. Install with:"
    echo "  apt-get install ldap-utils    # Debian/Ubuntu"
    echo "  yum install openldap-clients   # RHEL/CentOS"
    echo
    echo "Or use the Go test tool:"
    echo "  go run ./cmd/verify-ldap-picture"
fi
