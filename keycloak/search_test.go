package keycloak

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glauth/ldap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestSearchSessionNil(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	h.sessions["default"] = nil
	req := ldap.SearchRequest{BaseDN: "", Scope: ldap.ScopeBaseObject, Filter: "(objectclass=*)", Attributes: []string{}, Controls: []ldap.Control{}}
	res, err := h.Search("cn=bind,dc=example,dc=com", req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestSearchWrongBoundDN(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	dn := "cn=alice,cn=users,dc=example,dc=com"
	h.sessions["default"] = &session{boundDN: &dn, token: &oauth2.Token{AccessToken: "x"}}
	req := ldap.SearchRequest{BaseDN: "", Scope: ldap.ScopeBaseObject, Filter: "(objectclass=*)", Attributes: []string{}, Controls: []ldap.Control{}}
	res, err := h.Search("cn=bob,cn=users,dc=example,dc=com", req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestSearchRootDSE(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "", Scope: ldap.ScopeBaseObject, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectclass=*)", Attributes: []string{}, Controls: []ldap.Control{},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1)
	assert.Empty(t, res.Entries[0].DN)
}

func TestSearchUsers(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{Username: "alice", FirstName: "Alice", LastName: "A", Email: "alice@example.com"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, "cn=alice,cn=users,dc=example,dc=com", res.Entries[0].DN)
}

func TestJellyfinExactUserLookup(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{ID: "alice-id", Username: "alice", FirstName: "Alice", LastName: "A", Email: "alice@example.com"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	// Jellyfin builds this when user logs in: exact match on username or mail (no wildcard).
	exactFilter := "(&(objectClass=user)(|(sAMAccountName=alice)(mail=alice@example.com)))"
	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: exactFilter, Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, "cn=alice,cn=users,dc=example,dc=com", res.Entries[0].DN)
}

func TestJellyfinExactUserLookupOrderAgnostic(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{ID: "alice-id", Username: "alice", FirstName: "Alice", LastName: "A", Email: "alice@example.com"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	orderAgnosticFilter := "(&(objectClass=user)(|(cn=alice)(mail=alice@example.com)(sAMAccountName=alice)))"
	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: orderAgnosticFilter, Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, "cn=alice,cn=users,dc=example,dc=com", res.Entries[0].DN)
}

func TestSearchUsersWithPrefix(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{Username: "alice", FirstName: "Alice", LastName: "A", Email: "alice@example.com"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter:     "(&(objectClass=user)(|(sAMAccountName=al*)(sn=al*)(givenName=al*)(cn=al*)(displayname=al*)(userPrincipalName=al*)))",
		Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	assert.Len(t, res.Entries, 1)
}

func TestSearchGroups(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/groups" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]Group{{ID: "1", Name: "admins"}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=groups,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter:     "(&(objectClass=group)(|(sAMAccountName=ad*)(cn=ad*)))",
		Attributes: attributes3, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, "cn=admins,cn=groups,dc=example,dc=com", res.Entries[0].DN)
}

func TestSearchUserBoundUserinfo(t *testing.T) {
	userinfoResp := map[string]interface{}{
		"sub":                "sub-id",
		"preferred_username": "alice",
		"given_name":         "Alice",
		"family_name":        "A",
		"email":              "alice@example.com",
	}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(userinfoResp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=alice,cn=users,dc=example,dc=com", "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, "cn=alice,cn=users,dc=example,dc=com", res.Entries[0].DN)
}

func TestSearchUnexpectedRequestParams(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	dn := "cn=svc,cn=bind,dc=example,dc=com"
	h.sessions["default"] = &session{boundDN: &dn, token: &oauth2.Token{AccessToken: "x"}}

	req := ldap.SearchRequest{
		BaseDN: "", Scope: ldap.ScopeBaseObject, DerefAliases: ldap.DerefAlways,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectclass=*)", Attributes: []string{}, Controls: []ldap.Control{},
	}
	res, err := h.Search(dn, req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestSearchUnexpectedBaseDN(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "ou=other,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestSearchUserBoundUserinfoPreferredNameFromSub(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"sub": "sub-id-only", "given_name": "A", "family_name": "B", "email": "a@b.com"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	boundDN := "cn=alice,cn=users,dc=example,dc=com"
	code, _ := h.Bind(boundDN, "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, boundDN, res.Entries[0].DN)
}

func TestSearchUserBoundBaseDNMismatch(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"preferred_username": "alice", "sub": "x", "given_name": "A", "family_name": "B", "email": "a@b.com"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=alice,cn=users,dc=example,dc=com", "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "ou=other,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	assert.Empty(t, res.Entries)
}

func TestSearchUserBoundFilterNoMatch(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"preferred_username": "alice", "sub": "x", "given_name": "A", "family_name": "B", "email": "a@b.com"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=alice,cn=users,dc=example,dc=com", "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=alice,cn=users,dc=example,dc=com", Scope: ldap.ScopeBaseObject, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=group)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	assert.Empty(t, res.Entries)
}

func TestSearchUserBoundUserinfoFails(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=alice,cn=users,dc=example,dc=com", "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestSearchUsersKeycloakGetError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestSearchGroupsKeycloakGetError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/groups" && r.Method == "GET" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=groups,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter:     "(&(objectClass=group)(|(sAMAccountName=x*)(cn=x*)))",
		Attributes: attributes3, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestSearchUnexpectedSizeLimit(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	dn := "cn=svc,cn=bind,dc=example,dc=com"
	h.sessions["default"] = &session{boundDN: &dn, token: &oauth2.Token{AccessToken: "x"}}

	req := ldap.SearchRequest{
		BaseDN: "", Scope: ldap.ScopeBaseObject, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 1, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectclass=*)", Attributes: []string{}, Controls: []ldap.Control{},
	}
	res, err := h.Search(dn, req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestSearchUnexpectedTimeLimit(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	dn := "cn=svc,cn=bind,dc=example,dc=com"
	h.sessions["default"] = &session{boundDN: &dn, token: &oauth2.Token{AccessToken: "x"}}

	req := ldap.SearchRequest{
		BaseDN: "", Scope: ldap.ScopeBaseObject, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 1, TypesOnly: false,
		Filter: "(objectclass=*)", Attributes: []string{}, Controls: []ldap.Control{},
	}
	res, err := h.Search(dn, req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestSearchUnexpectedTypesOnly(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	dn := "cn=svc,cn=bind,dc=example,dc=com"
	h.sessions["default"] = &session{boundDN: &dn, token: &oauth2.Token{AccessToken: "x"}}

	req := ldap.SearchRequest{
		BaseDN: "", Scope: ldap.ScopeBaseObject, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: true,
		Filter: "(objectclass=*)", Attributes: []string{}, Controls: []ldap.Control{},
	}
	res, err := h.Search(dn, req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestSearchUserBoundScopeSingleLevel(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"preferred_username": "alice", "sub": "x", "given_name": "A", "family_name": "B", "email": "a@b.com"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=alice,cn=users,dc=example,dc=com", "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=alice,cn=users,dc=example,dc=com", Scope: ldap.ScopeSingleLevel, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 0)
}

func TestSearchWithUnknownControlType(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	unknownControl := ldap.NewControlString("1.2.3.4.5", false, "")
	req := ldap.SearchRequest{
		BaseDN: "ou=other,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{unknownControl},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestSearchUserBoundScopeNotSupported(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"preferred_username": "alice", "sub": "x", "given_name": "A", "family_name": "B", "email": "a@b.com"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=alice,cn=users,dc=example,dc=com", "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: 99, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	assert.Empty(t, res.Entries)
}

func TestSearchUserBoundUserinfoInvalidJSON(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not json"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=alice,cn=users,dc=example,dc=com", "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	assert.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
}

func TestUserBoundSearchWithBaseDNBoundDNReturnsEntry(t *testing.T) {
	userinfoResp := map[string]interface{}{
		"sub":                "sub-id",
		"preferred_username": "bob",
		"given_name":         "Bob",
		"family_name":        "B",
		"email":              "bob@example.com",
	}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(userinfoResp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)

	boundDN := "cn=alice,cn=users,dc=example,dc=com"
	code, _ := h.Bind(boundDN, "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: boundDN, Scope: ldap.ScopeBaseObject, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)

	require.Len(t, res.Entries, 1, "boundDN base object search should return one entry")
	assert.Equal(t, boundDN, res.Entries[0].DN)
}

func TestSearchUsersWithPrefixNoMatch(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{Username: "alice", FirstName: "Alice", LastName: "A", Email: "alice@example.com"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter:     "(&(objectClass=user)(|(sAMAccountName=z*)(sn=z*)(givenName=z*)(cn=z*)(displayname=z*)(userPrincipalName=z*)))",
		Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	assert.Empty(t, res.Entries)
}

func TestSearchUsersWithUserPrincipalNamePrefix(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{Username: "alice", FirstName: "Alice", LastName: "A", Email: "other@example.net"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter:     "(&(objectClass=user)(|(sAMAccountName=alice@*)(sn=alice@*)(givenName=alice@*)(cn=alice@*)(displayname=alice@*)(userPrincipalName=alice@*)))",
		Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	assert.Len(t, res.Entries, 1, "userPrincipalName prefix should match and return entry")
}

func TestSearchGroupsPrefixNoMatch(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/groups" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]Group{{ID: "1", Name: "admins"}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=groups,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter:     "(&(objectClass=group)(|(sAMAccountName=z*)(cn=z*)))",
		Attributes: attributes3, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	assert.Empty(t, res.Entries)
}

func TestUserBoundEntryAttributesMatchBoundDN(t *testing.T) {
	userinfoResp := map[string]interface{}{
		"preferred_username": "bob",
		"sub":                "sub-id",
		"given_name":         "Bob",
		"family_name":        "B",
		"email":              "bob@example.com",
	}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(userinfoResp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)

	boundDN := "cn=alice,cn=users,dc=example,dc=com"
	code, _ := h.Bind(boundDN, "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: boundDN, Scope: ldap.ScopeBaseObject, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1)
	entry := res.Entries[0]

	cnAttr := entry.GetAttributeValue("cn")
	samAccountNameAttr := entry.GetAttributeValue("sAMAccountName")
	assert.Equal(t, "alice", cnAttr, "cn should match boundDN when entry DN is boundDN")
	assert.Equal(t, "alice", samAccountNameAttr, "sAMAccountName should match boundDN when entry DN is boundDN")
}

func TestSearchUsersWithPrefixIsCaseInsensitive(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{Username: "alice", FirstName: "Alice", LastName: "A", Email: "alice@example.com"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter:     "(&(objectClass=user)(|(sAMAccountName=AL*)(sn=AL*)(givenName=AL*)(cn=AL*)(displayname=AL*)(userPrincipalName=AL*)))",
		Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	assert.Len(t, res.Entries, 1, "prefix match should be case-insensitive")
}

func TestSearchUserBoundUserinfoWithGroupsAndRoles(t *testing.T) {
	userinfoResp := map[string]interface{}{
		"sub":                "sub-id",
		"preferred_username": "alice",
		"given_name":         "Alice",
		"family_name":        "A",
		"email":              "alice@example.com",
		"groups":             []string{"/admins", "/parent/developers"},
		"realm_access":       map[string]interface{}{"roles": []string{"user", "admin"}},
	}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(userinfoResp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=alice,cn=users,dc=example,dc=com", "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1)
	entry := res.Entries[0]

	memberOf := entry.GetAttributeValues("memberOf")
	require.NotEmpty(t, memberOf, "memberOf should contain group and role DNs")
	assert.Contains(t, memberOf, "cn=admins,cn=groups,dc=example,dc=com")
	assert.Contains(t, memberOf, "cn=developers,cn=groups,dc=example,dc=com")
	assert.Contains(t, memberOf, "cn=user,ou=roles,dc=example,dc=com")
	assert.Contains(t, memberOf, "cn=admin,ou=roles,dc=example,dc=com")
	assert.Len(t, memberOf, 4)
}

func TestSearchUserBoundUserinfoWithRolesOnly(t *testing.T) {
	userinfoResp := map[string]interface{}{
		"sub":                "sub-id",
		"preferred_username": "bob",
		"realm_access":       map[string]interface{}{"roles": []string{"viewer"}},
	}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(userinfoResp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=bob,cn=users,dc=example,dc=com", "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.Len(t, res.Entries, 1)
	entry := res.Entries[0]

	memberOf := entry.GetAttributeValues("memberOf")
	assert.Contains(t, memberOf, "cn=viewer,ou=roles,dc=example,dc=com")
}

func TestSearchUserBoundUserinfoWithGroupsOnly(t *testing.T) {
	userinfoResp := map[string]interface{}{
		"sub":                "sub-id",
		"preferred_username": "charlie",
		"groups":             []string{"/team-a"},
	}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(userinfoResp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=charlie,cn=users,dc=example,dc=com", "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.Len(t, res.Entries, 1)
	entry := res.Entries[0]

	memberOf := entry.GetAttributeValues("memberOf")
	assert.Equal(t, []string{"cn=team-a,cn=groups,dc=example,dc=com"}, memberOf)
}

func TestSearchUserBoundMemberOfJellyfinStyle(t *testing.T) {
	userinfoResp := map[string]interface{}{
		"sub":                "sub-id",
		"preferred_username": "test",
		"realm_access":       map[string]interface{}{"roles": []string{"jellyfin-users", "jellyfin-admins"}},
	}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(userinfoResp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	config.ldapDomain = "societycell.local"
	h := makeHandlerWithConfig(config)

	boundDN := "cn=test,cn=users,dc=societycell,dc=local"
	code, _ := h.Bind(boundDN, "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=societycell,dc=local", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.Len(t, res.Entries, 1)
	entry := res.Entries[0]

	memberOf := entry.GetAttributeValues("memberOf")
	require.NotEmpty(t, memberOf, "memberOf required for filter (|(memberOf=cn=jellyfin-users,...)(memberOf=cn=jellyfin-admins,...))")
	jellyfinUsersDN := "cn=jellyfin-users,ou=roles,dc=societycell,dc=local"
	jellyfinAdminsDN := "cn=jellyfin-admins,ou=roles,dc=societycell,dc=local"
	assert.Contains(t, memberOf, jellyfinUsersDN, "entry must have memberOf for jellyfin-users so Jellyfin-style filter matches")
	assert.Contains(t, memberOf, jellyfinAdminsDN, "entry must have memberOf for jellyfin-admins so Jellyfin-style filter matches")
}

func TestSearchMemberOfRolesUsesRoleNameInAPIPath(t *testing.T) {
	var rolesUsersPathReceived string
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin/realms/test/roles/") && strings.HasSuffix(r.URL.Path, "/users") && r.Method == "GET" {
			rolesUsersPathReceived = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{ID: "user-1", Username: "alice", FirstName: "Alice", LastName: "A", Email: "alice@example.com"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.ldapDomain = "example.com"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	memberOfRolesFilter := "(|(memberOf=cn=jellyfin-users,ou=roles,dc=example,dc=com))"
	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: memberOfRolesFilter, Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)

	require.Equal(t, "/admin/realms/test/roles/jellyfin-users/users", rolesUsersPathReceived,
		"Keycloak roles endpoint expects role name in path (roles/{role-name}/users), not role ID; got path %q", rolesUsersPathReceived)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, "cn=alice,cn=users,dc=example,dc=com", res.Entries[0].DN)
}

func TestPortForwardTestLapJellyfinExactUser(t *testing.T) {
	baseDN := "dc=societycell,dc=local"
	bindUser := "test"
	userinfoResp := map[string]interface{}{
		"sub":                "sub-test",
		"preferred_username": bindUser,
		"given_name":         "Test",
		"family_name":        "User",
		"email":              "test@example.com",
	}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(userinfoResp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	config.userinfoEndpointURL = tokenServer.URL + "/userinfo"
	config.ldapDomain = "societycell.local"
	h := makeHandlerWithConfig(config)

	bindDN := "cn=" + bindUser + ",cn=users," + baseDN
	code, _ := h.Bind(bindDN, "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code, "bind as user test must succeed")

	usersBase := "cn=users," + baseDN
	exactFilter := "(&(objectClass=user)(|(sAMAccountName=" + bindUser + ")(mail=" + bindUser + ")(cn=" + bindUser + ")))"
	req := ldap.SearchRequest{
		BaseDN: usersBase, Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter:     exactFilter,
		Attributes: []string{"sAMAccountName", "userPrincipalName", "cn", "mail"},
		Controls:   []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1, "exact user lookup (Jellyfin-style) must return at least one entry for bound user %q", bindUser)
	assert.Equal(t, "cn="+bindUser+","+usersBase, res.Entries[0].DN)
}
