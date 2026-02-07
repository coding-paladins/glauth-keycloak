// One-off: verify LDAP bind with Keycloak client ID (service account).
// Usage: LDAP_BIND_DN="cn=glauth-ldap,cn=bind,dc=societycell,dc=local" LDAP_BIND_PW="secret" go run ./cmd/verify-ldap-bind
package main

import (
	"fmt"
	"os"

	"github.com/go-ldap/ldap/v3"
)

func main() {
	url := getEnv("LDAP_URL", "ldap://127.0.0.1:3893")
	bindDN := getEnv("LDAP_BIND_DN", "")
	bindPW := getEnv("LDAP_BIND_PW", "")
	if bindDN == "" || bindPW == "" {
		fmt.Fprintln(os.Stderr, "set LDAP_BIND_DN and LDAP_BIND_PW (e.g. cn=glauth-ldap,cn=bind,dc=societycell,dc=local and client secret)")
		os.Exit(1)
	}

	conn, err := ldap.DialURL(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPW); err != nil {
		fmt.Fprintf(os.Stderr, "bind failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("bind: success (client ID + secret work for Jellyfin LDAP bind)")

	// Root DSE (no Keycloak call)
	result, err := conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectclass=*)", nil, nil,
	))
	if err != nil {
		fmt.Fprintf(os.Stderr, "root DSE search failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("root DSE search: %d entries\n", len(result.Entries))

	// Users search (hits Keycloak; may fail if realm has no users or permissions)
	base := "cn=users,dc=societycell,dc=local"
	usersResult, err := conn.Search(ldap.NewSearchRequest(
		base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)",
		[]string{"cn", "uid", "mail"},
		nil,
	))
	if err != nil {
		fmt.Printf("users search failed (Keycloak/realm config?): %v\n", err)
		return
	}
	fmt.Printf("users search (%s): %d entries\n", base, len(usersResult.Entries))
	for _, e := range usersResult.Entries {
		fmt.Printf("  - %s (cn=%s)\n", e.DN, e.GetAttributeValue("cn"))
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
