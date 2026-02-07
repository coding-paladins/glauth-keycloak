package keycloak

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/glauth/ldap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterMemberOfUsers(t *testing.T) {
	filter := "(|(memberOf=cn=jellyfin-users,ou=groups,dc=ldap,dc=goauthentik,dc=io)(memberOf=cn=jellyfin-admins,ou=groups,dc=ldap,dc=goauthentik,dc=io))"
	names := extractMemberOfGroupNames(filter)
	assert.Len(t, names, 2)
	assert.Contains(t, names, "jellyfin-users")
	assert.Contains(t, names, "jellyfin-admins")
}

func TestExtractMemberOfGroupNames(t *testing.T) {
	filter := "(|(memberOf=cn=group-a,cn=groups,dc=example,dc=com)(memberOf=cn=group-b,cn=groups,dc=example,dc=com))"
	names := extractMemberOfGroupNames(filter)
	assert.Len(t, names, 2)
	assert.Contains(t, names, "group-a")
	assert.Contains(t, names, "group-b")
}

func TestExtractMemberOfRoleNames(t *testing.T) {
	filter := "(|(memberOf=cn=default-roles-societycell,ou=roles,dc=example,dc=com)(memberOf=cn=uma_authorization,ou=roles,dc=example,dc=com))"
	names := extractMemberOfRoleNames(filter)
	assert.Len(t, names, 2)
	assert.Contains(t, names, "default-roles-societycell")
	assert.Contains(t, names, "uma_authorization")
}

func TestMemberOfRolesSearchRoleNames(t *testing.T) {
	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com",
		Filter: "(|(memberOf=cn=jellyfin-users,ou=roles,dc=example,dc=com))",
	}
	names := memberOfRolesSearchRoleNames(req)
	require.Len(t, names, 1, "memberOf roles filter should yield one role name")
	assert.Equal(t, "jellyfin-users", names[0])
}

func TestSid(t *testing.T) {
	s := sidToString(sid("4e292dae-35db-4f1a-b40b-17e8e0a3a6b7", "domain.com"))
	assert.True(t, strings.HasPrefix(s, "S-1-5-21-"), "SID should be NT authority, domain-relative")
	parts := strings.Split(s, "-")
	assert.GreaterOrEqual(t, len(parts), 5, "SID should have revision + identifier authority + sub-authorities")
}

func TestParseUsernameFromUserBindDN(t *testing.T) {
	baseDN := "cn=users,dc=example,dc=com"
	tests := []struct {
		name     string
		bindDN   string
		baseDN   string
		wantUser string
		wantOK   bool
	}{
		{"valid simple", "cn=johndoe,cn=users,dc=example,dc=com", baseDN, "johndoe", true},
		{"valid with hyphen", "cn=mary-jane,cn=users,dc=example,dc=com", baseDN, "mary-jane", true},
		{"wrong suffix", "cn=johndoe,ou=people,dc=example,dc=com", baseDN, "", false},
		{"no cn prefix", "uid=johndoe,cn=users,dc=example,dc=com", baseDN, "", false},
		{"empty username", "cn=,cn=users,dc=example,dc=com", baseDN, "", false}, // After fix: should reject empty username
		{"bind base", "cn=myclient,cn=bind,dc=example,dc=com", "cn=bind,dc=example,dc=com", "myclient", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUser, gotOK := parseUsernameFromUserBindDN(tt.bindDN, tt.baseDN)
			assert.Equal(t, tt.wantOK, gotOK)
			assert.Equal(t, tt.wantUser, gotUser)
		})
	}
}

func TestNewAttribute(t *testing.T) {
	a := newAttribute("cn", "johndoe")
	require.NotNil(t, a)
	assert.Equal(t, "cn", a.Name)
	assert.Len(t, a.Values, 1)
	assert.Equal(t, "johndoe", a.Values[0])
}

func TestParseUsernameFromUserBindDNWithCommaInRDN(t *testing.T) {
	baseDN := "cn=users,dc=example,dc=com"
	gotUser, gotOK := parseUsernameFromUserBindDN("cn=foo,bar,cn=users,dc=example,dc=com", baseDN)
	assert.False(t, gotOK)
	assert.Empty(t, gotUser)
}

func TestParseFirstCNValueFromBindDNWithSuffixRejectsUnescapedComma(t *testing.T) {
	got, ok := parseFirstCNValueFromBindDNWithSuffix("cn=my,client,cn=bind,dc=example,dc=com", ",cn=bind,dc=example,dc=com")
	assert.False(t, ok)
	assert.Empty(t, got)
}

func TestParseFirstCNValueFromBindDNWithSuffixServiceAccount(t *testing.T) {
	// Escaped comma in first RDN value.
	got, ok := parseFirstCNValueFromBindDNWithSuffix("cn=my\\,client,cn=bind,dc=example,dc=com", ",cn=bind,dc=example,dc=com")
	require.True(t, ok)
	assert.Equal(t, "my,client", got)
}

func TestBugReview_DNValuesNotEscaped(t *testing.T) {
	baseDNUsers := "cn=users,dc=example,dc=com"
	ldapDomain := "example.com"

	userWithComma := User{ID: "id1", Username: "foo,bar", FirstName: "F", LastName: "L", Email: "e@e.com"}
	entry := userToLDAPEntry(userWithComma, baseDNUsers, ldapDomain)
	if entry == nil {
		t.Fatal("userToLDAPEntry returned nil")
	}
	// Unescaped "foo,bar" would be parsed as two RDNs; escaped form is "foo\,bar" (backslash before comma)
	assert.NotContains(t, entry.DN, "foo,bar", "DN must not contain unescaped comma so it is not parsed as separate RDN")
	assert.Contains(t, entry.DN, "foo\\,bar", "DN should contain escaped comma")

	groupWithEquals := Group{ID: "g1", Name: "role=admin"}
	groupEntry := groupToLDAPEntry(groupWithEquals, "cn=groups,dc=example,dc=com", ldapDomain)
	require.NotNil(t, groupEntry)
	assert.Contains(t, groupEntry.DN, `\=`, "DN should escape equals in group name")
}

func TestBugReview_SidToStringPanicsOnShortInput(t *testing.T) {
	got := sidToString([]byte{1, 5})
	assert.Equal(t, "", got)
}

func TestBugConfirm_ParseCommonNameFromDNEscapedComma(t *testing.T) {
	// DN with escaped comma in first RDN value (RFC 4514: comma in value is written as \,).
	dn := "cn=foo\\,bar,dc=example,dc=com"
	got, ok := parseCommonNameFromDN(dn)
	require.True(t, ok)
	assert.Equal(t, "foo,bar", got)
}

func TestBugConfirm_ParseUsernameFromUserBindDNEscapedComma(t *testing.T) {
	baseDNUsers := "cn=users,dc=example,dc=com"
	// Bind DN with escaped comma in cn (e.g. username "foo,bar").
	bindDN := "cn=foo\\,bar,cn=users,dc=example,dc=com"
	gotUser, gotOK := parseUsernameFromUserBindDN(bindDN, baseDNUsers)
	require.True(t, gotOK)
	assert.Equal(t, "foo,bar", gotUser)
}

func TestBugConfirm_EscapeRDNValueControlCharacter(t *testing.T) {
	valueWithNul := "x\x00y"
	got := escapeRDNValue(valueWithNul)
	assert.Contains(t, got, "\\00", "control character NUL should be escaped as \\00")
	assert.NotEqual(t, valueWithNul, got)
}

func TestGroupPathToCN(t *testing.T) {
	tests := []struct {
		path   string
		expect string
	}{
		{"/admins", "admins"},
		{"/parent/child", "child"},
		{"", ""},
		{"noslash", "noslash"},
		{" /a ", "a"},
		{"/single", "single"},
		{"/a/b/c", "c"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := groupPathToCN(tt.path)
			assert.Equal(t, tt.expect, got)
		})
	}
}

func TestRealmRolesFromUserinfo(t *testing.T) {
	t.Run("nil_info_returns_nil", func(t *testing.T) {
		got := realmRolesFromUserinfo(nil)
		assert.Nil(t, got)
	})
	t.Run("empty_info_returns_nil", func(t *testing.T) {
		got := realmRolesFromUserinfo(&userinfoResponse{})
		assert.Nil(t, got)
	})
	t.Run("realm_roles_takes_precedence", func(t *testing.T) {
		var info userinfoResponse
		err := json.Unmarshal([]byte(`{"realm_roles":["r1","r2"],"realm_access":{"roles":["other"]}}`), &info)
		require.NoError(t, err)
		got := realmRolesFromUserinfo(&info)
		assert.Equal(t, []string{"r1", "r2"}, got)
	})
	t.Run("realm_access_roles_used_when_realm_roles_empty", func(t *testing.T) {
		var info userinfoResponse
		err := json.Unmarshal([]byte(`{"realm_access":{"roles":["admin","user"]}}`), &info)
		require.NoError(t, err)
		got := realmRolesFromUserinfo(&info)
		assert.Equal(t, []string{"admin", "user"}, got)
	})
	t.Run("nil_realm_access_returns_nil", func(t *testing.T) {
		info := &userinfoResponse{} // Roles not set
		got := realmRolesFromUserinfo(info)
		assert.Nil(t, got)
	})
	t.Run("empty_realm_access_roles_returns_nil", func(t *testing.T) {
		var info userinfoResponse
		err := json.Unmarshal([]byte(`{"realm_access":{"roles":[]}}`), &info)
		require.NoError(t, err)
		got := realmRolesFromUserinfo(&info)
		assert.Nil(t, got)
	})
	t.Run("realm_and_client_roles_combined_client_prefix", func(t *testing.T) {
		var info userinfoResponse
		err := json.Unmarshal([]byte(`{
			"realm_access": {"roles": ["admin", "user"]},
			"resource_access": {
				"jellyfin": {"roles": ["jellyfin-users", "jellyfin-admins"]},
				"other-client": {"roles": ["viewer"]}
			}
		}`), &info)
		require.NoError(t, err)
		got := realmRolesFromUserinfo(&info)
		// Realm roles first (order from realm_access), then client roles with "clientId:roleName"
		assert.Contains(t, got, "admin")
		assert.Contains(t, got, "user")
		assert.Contains(t, got, "jellyfin:jellyfin-users")
		assert.Contains(t, got, "jellyfin:jellyfin-admins")
		assert.Contains(t, got, "other-client:viewer")
		assert.Len(t, got, 5)
	})
}
