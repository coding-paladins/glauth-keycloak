// Program test-ldap connects to a GLAuth LDAP server (e.g. port-forwarded pod),
// binds as a user, runs the supported search operations, and runs security probes
// to check for common vulnerability patterns.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func main() {
	ldapURL := getEnv("LDAP_URL", "ldap://127.0.0.1:3893")
	baseDN := getBaseDN()
	bindUser := getEnv("LDAP_USER", "test")
	bindPassword := getEnv("LDAP_PASSWORD", "test")

	connection, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial failed: %v\n", err)
		os.Exit(1)
	}
	defer connection.Close()

	runFeatureTests(connection, baseDN, bindUser, bindPassword)
	fmt.Println()

	runSecurityProbes(ldapURL, baseDN, bindUser, bindPassword)
}

func runFeatureTests(connection *ldap.Conn, baseDN, bindUser, bindPassword string) {
	bindDN := fmt.Sprintf("cn=%s,cn=users,%s", bindUser, baseDN)
	if err := connection.Bind(bindDN, bindPassword); err != nil {
		fmt.Fprintf(os.Stderr, "bind failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("bind: success (user " + bindUser + ")")

	usersBase := "cn=users," + baseDN
	groupsBase := "cn=groups," + baseDN

	rootDSE, err := connection.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectclass=*)", nil, nil,
	))
	if err != nil {
		fmt.Fprintf(os.Stderr, "root DSE search failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("root DSE search: %d entries\n", len(rootDSE.Entries))

	usersResult, err := connection.Search(ldap.NewSearchRequest(
		usersBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)",
		[]string{"sAMAccountName", "userPrincipalName", "description", "givenName", "sn", "mail", "userAccountControl", "lockoutTime", "objectSid"},
		[]ldap.Control{ldap.NewControlPaging(100)},
	))
	if err != nil {
		fmt.Fprintf(os.Stderr, "users search failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("users search: %d entries\n", len(usersResult.Entries))

	usersPrefixResult, err := connection.Search(ldap.NewSearchRequest(
		usersBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=user)(|(sAMAccountName=te*)(sn=te*)(givenName=te*)(cn=te*)(displayname=te*)(userPrincipalName=te*)))",
		[]string{"sAMAccountName", "userPrincipalName", "description", "givenName", "sn", "mail", "userAccountControl", "lockoutTime", "objectSid"},
		[]ldap.Control{ldap.NewControlPaging(100)},
	))
	if err != nil {
		fmt.Fprintf(os.Stderr, "users prefix search failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("users prefix (te*) search: %d entries\n", len(usersPrefixResult.Entries))

	// Jellyfin-style exact user lookup: (&(objectClass=user)(|(sAMAccountName={user})(mail={user})(cn={user}))).
	// Must return at least one entry for the bound user.
	exactFilter := buildJellyfinExactUserFilter(bindUser)
	exactResult, exactErr := connection.Search(ldap.NewSearchRequest(
		usersBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		exactFilter,
		[]string{"sAMAccountName", "userPrincipalName", "cn", "mail"},
		[]ldap.Control{ldap.NewControlPaging(100)},
	))
	if exactErr != nil {
		fmt.Fprintf(os.Stderr, "exact user lookup (Jellyfin-style) failed: %v\n", exactErr)
		os.Exit(1)
	}
	fmt.Printf("exact user lookup (Jellyfin-style): %d entries\n", len(exactResult.Entries))
	if len(exactResult.Entries) < 1 {
		fmt.Fprintf(os.Stderr, "exact user lookup returned 0 entries; expected at least one for user %q\n", bindUser)
		os.Exit(1)
	}

	groupsResult, err := connection.Search(ldap.NewSearchRequest(
		groupsBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=group)(|(sAMAccountName=t*)(cn=t*)))",
		[]string{"sAMAccountName", "description", "objectSid"},
		[]ldap.Control{ldap.NewControlPaging(100)},
	))
	if err != nil {
		fmt.Fprintf(os.Stderr, "groups search failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("groups search (prefix t*): %d entries\n", len(groupsResult.Entries))

	// Get test user's groups from their entry (memberOf) when bound as user
	userGroups := getTestUserGroups(connection, usersBase)
	memberOfGroups := getEnv("LDAP_MEMBEROF_GROUPS", "")
	if memberOfGroups == "" && len(userGroups) > 0 {
		memberOfGroups = strings.Join(userGroups, ",")
		fmt.Printf("test user groups (from memberOf): %s\n", memberOfGroups)
	}
	if memberOfGroups == "" {
		memberOfGroups = "jellyfin-users,jellyfin-admins"
		fmt.Println("no test user groups found, using default for memberOf: " + memberOfGroups)
	}
	memberOfFilter := buildMemberOfFilter(memberOfGroups, groupsBase)
	memberOfResult, err := connection.Search(ldap.NewSearchRequest(
		usersBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		memberOfFilter,
		[]string{"sAMAccountName", "userPrincipalName", "description", "givenName", "sn", "mail", "userAccountControl", "lockoutTime", "objectSid"},
		[]ldap.Control{ldap.NewControlPaging(100)},
	))
	if err != nil {
		fmt.Fprintf(os.Stderr, "memberOf search failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("memberOf search (%s): %d entries\n", memberOfGroups, len(memberOfResult.Entries))

	// Same test with roles: get test user's roles from memberOf (ou=roles,...), then search users by those roles
	rolesBase := "ou=roles," + baseDN
	userRoles := getTestUserRoles(connection, usersBase)
	memberOfRoles := getEnv("LDAP_MEMBEROF_ROLES", "")
	if memberOfRoles == "" && len(userRoles) > 0 {
		memberOfRoles = strings.Join(userRoles, ",")
		fmt.Printf("test user roles (from memberOf): %s\n", memberOfRoles)
	}
	if memberOfRoles == "" {
		memberOfRoles = "default-roles-societycell"
		fmt.Println("no test user roles found, using default for memberOf roles: " + memberOfRoles)
	}
	memberOfRolesFilter := buildMemberOfFilter(memberOfRoles, rolesBase)
	memberOfRolesResult, err := connection.Search(ldap.NewSearchRequest(
		usersBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		memberOfRolesFilter,
		[]string{"sAMAccountName", "userPrincipalName", "description", "givenName", "sn", "mail", "userAccountControl", "lockoutTime", "objectSid"},
		[]ldap.Control{ldap.NewControlPaging(100)},
	))
	if err != nil {
		fmt.Fprintf(os.Stderr, "memberOf (roles) search failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("memberOf search by roles (%s): %d entries\n", memberOfRoles, len(memberOfRolesResult.Entries))

	// Real Keycloak check: role-based memberOf uses GET /admin/realms/{realm}/roles/{role-name}/users (role name, not ID).
	// If the handler used role ID instead, Keycloak would return 404 and we would get 0 entries or an error.
	if len(userRoles) > 0 && len(memberOfRolesResult.Entries) == 0 {
		fmt.Fprintf(os.Stderr, "memberOf (roles) search returned 0 entries but bound user has roles %v; Keycloak API may be called with role ID instead of role name\n", userRoles)
		os.Exit(1)
	}
	boundUserDN := fmt.Sprintf("cn=%s,%s", bindUser, usersBase)
	foundBoundUser := false
	for _, entry := range memberOfRolesResult.Entries {
		if entry.DN == boundUserDN {
			foundBoundUser = true
			break
		}
	}
	if len(userRoles) > 0 && !foundBoundUser && len(memberOfRolesResult.Entries) > 0 {
		fmt.Fprintf(os.Stderr, "memberOf (roles) search returned %d entries but bound user %q not among them; verify role name is used in Keycloak API path\n", len(memberOfRolesResult.Entries), boundUserDN)
		os.Exit(1)
	}
	if len(userRoles) > 0 {
		fmt.Println("memberOf (roles) real Keycloak check: passed (role name used in API path)")
	}

	fmt.Println("all features exercised successfully")
}

// getTestUserGroups returns group names from the bound user's memberOf attribute (user-bound search returns self with memberOf).
func getTestUserGroups(connection *ldap.Conn, usersBase string) []string {
	req := ldap.NewSearchRequest(
		usersBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)",
		[]string{"memberOf"},
		[]ldap.Control{ldap.NewControlPaging(100)},
	)
	result, err := connection.Search(req)
	if err != nil || result == nil || len(result.Entries) == 0 {
		return nil
	}
	var groupNames []string
	seen := make(map[string]bool)
	for _, entry := range result.Entries {
		for _, attr := range entry.Attributes {
			if attr.Name != "memberOf" {
				continue
			}
			for _, dn := range attr.Values {
				// memberOf value is like "cn=GROUPNAME,cn=groups,dc=..." or "cn=GROUPNAME,ou=groups,dc=..."
				name := parseGroupNameFromMemberOfDN(dn)
				if name != "" && !seen[name] {
					seen[name] = true
					groupNames = append(groupNames, name)
				}
			}
		}
	}
	return groupNames
}

// getTestUserRoles returns role names from the bound user's memberOf attribute where the DN contains ",ou=roles,".
func getTestUserRoles(connection *ldap.Conn, usersBase string) []string {
	req := ldap.NewSearchRequest(
		usersBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)",
		[]string{"memberOf"},
		[]ldap.Control{ldap.NewControlPaging(100)},
	)
	result, err := connection.Search(req)
	if err != nil || result == nil || len(result.Entries) == 0 {
		return nil
	}
	var roleNames []string
	seen := make(map[string]bool)
	for _, entry := range result.Entries {
		for _, attr := range entry.Attributes {
			if attr.Name != "memberOf" {
				continue
			}
			for _, dn := range attr.Values {
				if !strings.Contains(dn, ",ou=roles,") {
					continue
				}
				name := parseGroupNameFromMemberOfDN(dn)
				if name != "" && !seen[name] {
					seen[name] = true
					roleNames = append(roleNames, name)
				}
			}
		}
	}
	return roleNames
}

// parseGroupNameFromMemberOfDN extracts the first RDN cn value from a memberOf DN.
func parseGroupNameFromMemberOfDN(dn string) string {
	dn = strings.TrimSpace(dn)
	if dn == "" || !strings.HasPrefix(strings.ToLower(dn), "cn=") {
		return ""
	}
	dn = dn[3:]
	comma := strings.Index(dn, ",")
	if comma < 0 {
		return strings.TrimSpace(dn)
	}
	return strings.TrimSpace(dn[:comma])
}

// buildJellyfinExactUserFilter builds the filter Jellyfin sends for user lookup: exact match on username/mail/cn.
func buildJellyfinExactUserFilter(username string) string {
	// Jellyfin: (&(objectClass=user)(|(sAMAccountName={username})(mail={username})(cn={username}))).
	escaped := ldap.EscapeFilter(username)
	return "(&(objectClass=user)(|(sAMAccountName=" + escaped + ")(mail=" + escaped + ")(cn=" + escaped + ")))"
}

func buildMemberOfFilter(commaSeparatedGroups, groupsBaseDN string) string {
	groups := strings.Split(commaSeparatedGroups, ",")
	var parts []string
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		parts = append(parts, "(memberOf=cn="+g+","+groupsBaseDN+")")
	}
	if len(parts) == 0 {
		return "(|(memberOf=cn=none," + groupsBaseDN + "))"
	}
	return "(|" + strings.Join(parts, "") + ")"
}

func runSecurityProbes(ldapURL, baseDN, bindUser, bindPassword string) {
	fmt.Println("--- security probes ---")

	probeAnonymousBind(ldapURL, baseDN)
	probeEmptyPassword(ldapURL, baseDN, bindUser)
	probeWrongPassword(ldapURL, baseDN, bindUser)
	probeEmptyUsername(ldapURL, baseDN, bindPassword)
	probeDNWithSpecialCharacters(ldapURL, baseDN, bindPassword)
	probeWrongSuffixInBindDN(ldapURL, baseDN, bindPassword)
	probeSearchWithoutBind(ldapURL, baseDN)
	probeFilterInjection(ldapURL, baseDN, bindUser, bindPassword)
	probeBaseDNTraversal(ldapURL, baseDN, bindUser, bindPassword)
	probeUserBindWithServiceAccountDN(ldapURL, baseDN, bindUser, bindPassword)
	probeExcessiveUsernameLength(ldapURL, baseDN)
}

func probeAnonymousBind(ldapURL, baseDN string) {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Println("  [anonymous bind] SKIP: dial failed")
		return
	}
	defer conn.Close()
	err = conn.UnauthenticatedBind("")
	if err != nil {
		fmt.Println("  [anonymous bind] PASS: unauthenticated bind rejected")
		return
	}
	// If we got here, anonymous bind succeeded; try search to see if we get data
	usersBase := "cn=users," + baseDN
	result, searchErr := conn.Search(ldap.NewSearchRequest(
		usersBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)", []string{"sAMAccountName"}, []ldap.Control{ldap.NewControlPaging(100)},
	))
	if searchErr != nil || (result != nil && len(result.Entries) > 0) {
		fmt.Println("  [anonymous bind] CHECK: anonymous bind accepted; review if anonymous access is intended")
	} else {
		fmt.Println("  [anonymous bind] CHECK: anonymous bind accepted but search returned no data")
	}
}

func probeEmptyPassword(ldapURL, baseDN, bindUser string) {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Println("  [empty password] SKIP: dial failed")
		return
	}
	defer conn.Close()
	bindDN := fmt.Sprintf("cn=%s,cn=users,%s", bindUser, baseDN)
	err = conn.Bind(bindDN, "")
	if err != nil {
		fmt.Println("  [empty password] PASS: bind with empty password rejected")
		return
	}
	fmt.Println("  [empty password] FAIL: bind with empty password accepted (possible vulnerability)")
}

func probeWrongPassword(ldapURL, baseDN, bindUser string) {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Println("  [wrong password] SKIP: dial failed")
		return
	}
	defer conn.Close()
	bindDN := fmt.Sprintf("cn=%s,cn=users,%s", bindUser, baseDN)
	err = conn.Bind(bindDN, "wrong-password-that-should-not-work")
	if err != nil {
		fmt.Println("  [wrong password] PASS: wrong password rejected")
		return
	}
	fmt.Println("  [wrong password] FAIL: wrong password accepted (authentication bypass)")
}

func probeEmptyUsername(ldapURL, baseDN, bindPassword string) {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Println("  [empty username] SKIP: dial failed")
		return
	}
	defer conn.Close()
	// Bind with empty cn value: cn=,cn=users,<baseDN>
	bindDN := "cn=,cn=users," + baseDN
	err = conn.Bind(bindDN, bindPassword)
	if err != nil {
		fmt.Println("  [empty username] PASS: bind with empty username rejected")
		return
	}
	fmt.Println("  [empty username] CHECK: bind with empty username accepted; ensure Keycloak does not treat empty username as valid")
}

func probeDNWithSpecialCharacters(ldapURL, baseDN, bindPassword string) {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Println("  [DN special chars] SKIP: dial failed")
		return
	}
	defer conn.Close()
	// Attempt DN that could be interpreted as filter injection if concatenated into a filter
	bindDN := "cn=test)(|(cn=*,cn=users," + baseDN
	err = conn.Bind(bindDN, bindPassword)
	if err != nil {
		fmt.Println("  [DN special chars] PASS: bind DN with )(|( rejected or parsed safely")
		return
	}
	fmt.Println("  [DN special chars] CHECK: bind with filter-like characters in DN succeeded; verify username sent to Keycloak is safe")
}

func probeWrongSuffixInBindDN(ldapURL, baseDN, bindPassword string) {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Println("  [wrong bind suffix] SKIP: dial failed")
		return
	}
	defer conn.Close()
	// Valid user name but wrong RDN path (ou=users instead of cn=users)
	bindDN := "cn=test,ou=users," + baseDN
	err = conn.Bind(bindDN, bindPassword)
	if err != nil {
		fmt.Println("  [wrong bind suffix] PASS: bind with wrong base path (ou=users) rejected")
		return
	}
	fmt.Println("  [wrong bind suffix] FAIL: bind with ou=users accepted; path should be cn=users only")
}

func probeSearchWithoutBind(ldapURL, baseDN string) {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Println("  [search without bind] SKIP: dial failed")
		return
	}
	defer conn.Close()
	usersBase := "cn=users," + baseDN
	_, err = conn.Search(ldap.NewSearchRequest(
		usersBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)", []string{"sAMAccountName"}, []ldap.Control{ldap.NewControlPaging(100)},
	))
	if err != nil {
		fmt.Println("  [search without bind] PASS: search without prior bind rejected")
		return
	}
	fmt.Println("  [search without bind] FAIL: search without bind returned data (information disclosure)")
}

func probeFilterInjection(ldapURL, baseDN, bindUser, bindPassword string) {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Println("  [filter injection] SKIP: dial failed")
		return
	}
	defer conn.Close()
	bindDN := fmt.Sprintf("cn=%s,cn=users,%s", bindUser, baseDN)
	if err := conn.Bind(bindDN, bindPassword); err != nil {
		fmt.Println("  [filter injection] SKIP: valid bind failed")
		return
	}
	usersBase := "cn=users," + baseDN
	// Send a filter that could broaden the search if interpreted as LDAP filter (e.g. match all)
	maliciousFilter := "(objectClass=user)(|(cn=*))"
	result, err := conn.Search(ldap.NewSearchRequest(
		usersBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		maliciousFilter, []string{"sAMAccountName"}, []ldap.Control{ldap.NewControlPaging(100)},
	))
	if err != nil {
		fmt.Println("  [filter injection] PASS: non-whitelisted filter rejected")
		return
	}
	if result != nil && len(result.Entries) > 1 {
		fmt.Println("  [filter injection] CHECK: filter returned multiple entries; confirm filter is not interpreted from client verbatim")
	} else {
		fmt.Println("  [filter injection] PASS: server only accepts expected filter shapes")
	}
}

func probeBaseDNTraversal(ldapURL, baseDN, bindUser, bindPassword string) {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Println("  [base DN traversal] SKIP: dial failed")
		return
	}
	defer conn.Close()
	bindDN := fmt.Sprintf("cn=%s,cn=users,%s", bindUser, baseDN)
	if err := conn.Bind(bindDN, bindPassword); err != nil {
		fmt.Println("  [base DN traversal] SKIP: valid bind failed")
		return
	}
	// Search with a different domain's base DN (traversal attempt)
	otherBase := "cn=users,dc=other,dc=evil,dc=com"
	result, err := conn.Search(ldap.NewSearchRequest(
		otherBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=user)", []string{"sAMAccountName"}, []ldap.Control{ldap.NewControlPaging(100)},
	))
	if err != nil {
		fmt.Println("  [base DN traversal] PASS: search with different base DN rejected or error")
		return
	}
	if result != nil && len(result.Entries) > 0 {
		fmt.Println("  [base DN traversal] FAIL: search returned data for different base DN (possible traversal)")
		return
	}
	fmt.Println("  [base DN traversal] PASS: no data returned for different base DN")
}

func probeUserBindWithServiceAccountDN(ldapURL, baseDN, bindUser, bindPassword string) {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Println("  [user creds on svc DN] SKIP: dial failed")
		return
	}
	defer conn.Close()
	// Try to bind as service account (cn=bind) using user credentials
	serviceBindDN := "cn=" + bindUser + ",cn=bind," + baseDN
	err = conn.Bind(serviceBindDN, bindPassword)
	if err != nil {
		fmt.Println("  [user creds on svc DN] PASS: user password not accepted for service account DN")
		return
	}
	fmt.Println("  [user creds on svc DN] CHECK: same password worked for cn=bind DN; ensure service and user credentials are separate")
}

func probeExcessiveUsernameLength(ldapURL, baseDN string) {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		fmt.Println("  [excessive username length] SKIP: dial failed")
		return
	}
	defer conn.Close()
	// Very long username (e.g. 64 KB) to check for DoS or buffer issues
	const excessiveLength = 64 * 1024
	longUsername := strings.Repeat("a", excessiveLength)
	bindDN := fmt.Sprintf("cn=%s,cn=users,%s", longUsername, baseDN)
	err = conn.Bind(bindDN, "any")
	if err != nil {
		fmt.Println("  [excessive username length] PASS: excessively long username rejected or error")
		return
	}
	fmt.Println("  [excessive username length] CHECK: server accepted very long username; ensure no DoS or buffer overflow")
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getBaseDN() string {
	if base := os.Getenv("LDAP_BASE_DN"); base != "" {
		return base
	}
	domain := getEnv("LDAP_DOMAIN", "example.com")
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")
	for i, p := range parts {
		parts[i] = "dc=" + p
	}
	return strings.Join(parts, ",")
}
