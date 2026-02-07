// verify LDAP jpegPhoto attribute is returned for users
// Usage: LDAP_BIND_DN="cn=glauth-ldap,cn=bind,dc=societycell,dc=local" LDAP_BIND_PW="secret" go run ./cmd/verify-ldap-picture
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
	baseDN := getEnv("LDAP_BASE_DN", "dc=societycell,dc=local")
	
	if bindDN == "" || bindPW == "" {
		fmt.Fprintln(os.Stderr, "set LDAP_BIND_DN and LDAP_BIND_PW")
		fmt.Fprintln(os.Stderr, "example: LDAP_BIND_DN=\"cn=glauth-ldap,cn=bind,dc=societycell,dc=local\" LDAP_BIND_PW=\"secret\"")
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
	fmt.Println("bind: success")

	// search for users with jpegPhoto attribute
	base := "cn=users," + baseDN
	usersResult, err := conn.Search(ldap.NewSearchRequest(
		base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)",
		[]string{"cn", "uid", "mail", "displayName", "jpegPhoto"},
		nil,
	))
	if err != nil {
		fmt.Printf("users search failed: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("\nusers search (%s): %d entries\n", base, len(usersResult.Entries))
	fmt.Println("----------------------------------------")
	
	hasAnyPicture := false
	for _, e := range usersResult.Entries {
		cn := e.GetAttributeValue("cn")
		uid := e.GetAttributeValue("uid")
		mail := e.GetAttributeValue("mail")
		jpegPhoto := e.GetAttributeValue("jpegPhoto")
		
		fmt.Printf("\nUser: %s\n", e.DN)
		fmt.Printf("  cn:          %s\n", cn)
		fmt.Printf("  uid:         %s\n", uid)
		fmt.Printf("  mail:        %s\n", mail)
		
		if jpegPhoto != "" {
			fmt.Printf("  jpegPhoto:   %s\n", jpegPhoto)
			hasAnyPicture = true
		} else {
			fmt.Printf("  jpegPhoto:   (not set)\n")
		}
	}
	
	fmt.Println("\n----------------------------------------")
	if hasAnyPicture {
		fmt.Println("✓ Found users with jpegPhoto attribute")
	} else {
		fmt.Println("✗ No users have jpegPhoto attribute set")
		fmt.Println("\nTo add a picture to a user in Keycloak:")
		fmt.Println("1. Go to Keycloak Admin Console")
		fmt.Println("2. Navigate to Users → Select a user → Attributes tab")
		fmt.Println("3. Add attribute: key='picture', value='https://example.com/avatar.jpg'")
		fmt.Println("4. Save the user")
		fmt.Println("5. Run this test again")
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
