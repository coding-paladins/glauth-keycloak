package keycloak

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glauth/ldap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchMemberOfUsesClientRoleMembersAPI(t *testing.T) {
	var compositePath string
	tokenServer := httptest.NewServer(withTestAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/realms/test/clients" && r.URL.Query().Get("clientId") == "jellyfin" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]keycloakClient{{ID: "client-uuid", ClientID: "jellyfin"}})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" && r.URL.Query().Get("username") == "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{ID: "user-1", Username: "admin", FirstName: "Admin", LastName: "User", Email: "admin@example.com"},
			})
			return
		}
		if r.URL.Path == "/admin/realms/test/users/user-1/role-mappings/clients/client-uuid/composite" && r.Method == "GET" {
			compositePath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]keycloakRole{
				{ID: "role-user", Name: "user"},
				{ID: "role-admin", Name: "admin"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.ldapClientID = "jellyfin"
	config.ldapClientSecret = "secret"
	config.ldapDomain = "societycell.local"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=jellyfin,cn=bind,dc=societycell,dc=local", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	filter := "(|(memberOf=cn=jellyfin-user,cn=groups,dc=societycell,dc=local)(memberOf=cn=jellyfin-admin,cn=groups,dc=societycell,dc=local))"
	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=societycell,dc=local", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: filter, Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Equal(t, "/admin/realms/test/users/user-1/role-mappings/clients/client-uuid/composite", compositePath)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, "cn=admin,cn=users,dc=societycell,dc=local", res.Entries[0].DN)
	memberOf := res.Entries[0].GetAttributeValues("memberOf")
	assert.Contains(t, memberOf, "cn=jellyfin-admin,cn=groups,dc=societycell,dc=local")
	assert.Contains(t, memberOf, "cn=jellyfin-user,cn=groups,dc=societycell,dc=local")
}

func TestBindUserRequiresClientRole(t *testing.T) {
	tokenServer := httptest.NewServer(withTestAuthForUser("jellyfin", "client-uuid", "bob", nil, nil))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.ldapClientID = "jellyfin"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=bob,cn=users,dc=example,dc=com", "pass", nil)
	assert.EqualValues(t, ldap.LDAPResultInvalidCredentials, code)
}

func TestBindUserAllowsClientRoleViaAdminAPI(t *testing.T) {
	tokenServer := httptest.NewServer(withTestAuthForUser("jellyfin", "client-uuid", "admin", []string{"admin"}, nil))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.ldapClientID = "jellyfin"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=admin,cn=users,dc=example,dc=com", "pass", nil)
	assert.EqualValues(t, ldap.LDAPResultSuccess, code)
}
