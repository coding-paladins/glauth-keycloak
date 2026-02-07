package keycloak

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	exactFilter := "(&(objectClass=user)(|(uid=alice)(mail=alice@example.com)))"
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

	orderAgnosticFilter := "(&(objectClass=user)(|(cn=alice)(mail=alice@example.com)(uid=alice)))"
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
		Filter:     "(&(objectClass=user)(|(uid=al*)(sn=al*)(givenName=al*)(cn=al*)(displayname=al*)(userPrincipalName=al*)))",
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

func TestSearchAcceptsSizeLimit(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	dn := "cn=svc,cn=bind,dc=example,dc=com"
	h.sessions["default"] = &session{boundDN: &dn, token: &oauth2.Token{AccessToken: "x"}, lastActivity: time.Now()}

	req := ldap.SearchRequest{
		BaseDN: "", Scope: ldap.ScopeBaseObject, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 1000, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectclass=*)", Attributes: []string{}, Controls: []ldap.Control{},
	}
	res, err := h.Search(dn, req, nil)
	assert.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
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

func TestSearchUserBoundScopeSingleLevelWithBaseUsers(t *testing.T) {
	// User-bound search with BaseDN cn=users and Scope SingleLevel exercises filterEntriesForRequest SingleLevel branch.
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
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeSingleLevel, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1, "single-level scope under cn=users should return bound user entry")
	assert.Equal(t, "cn=alice,cn=users,dc=example,dc=com", res.Entries[0].DN)
}

func TestValidateSearchRequestConstraintsSuccess(t *testing.T) {
	for _, sizeLimit := range []int{0, 1, 1000} {
		req := ldap.SearchRequest{
			BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases, SizeLimit: sizeLimit, TimeLimit: 0, TypesOnly: false,
		}
		err := validateSearchRequestConstraints(req)
		assert.NoError(t, err, "SizeLimit=%d should be accepted", sizeLimit)
	}
}

func TestIsSingleLevelScopeMatchInvalidEntryDN(t *testing.T) {
	assert.False(t, isSingleLevelScopeMatch("not a valid dn", "cn=users,dc=example,dc=com"))
}

func TestIsSingleLevelScopeMatchInvalidBaseDN(t *testing.T) {
	assert.False(t, isSingleLevelScopeMatch("cn=alice,cn=users,dc=example,dc=com", "invalid base"))
}

func TestIsSingleLevelScopeMatchRDNCountMismatch(t *testing.T) {
	// Entry must have exactly base+1 RDN; same depth as base returns false
	assert.False(t, isSingleLevelScopeMatch("cn=users,dc=example,dc=com", "cn=users,dc=example,dc=com"))
}

func TestIsSingleLevelScopeMatchRDNMismatch(t *testing.T) {
	// Entry under different base (ou=other vs cn=users)
	assert.False(t, isSingleLevelScopeMatch("cn=alice,ou=other,dc=example,dc=com", "cn=users,dc=example,dc=com"))
}

func TestFilterEntriesForRequestUnsupportedScope(t *testing.T) {
	entry := &ldap.Entry{DN: "cn=alice,cn=users,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{}}
	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: 99, Filter: "(objectClass=user)",
	}
	filtered, err := filterEntriesForRequest(req, []*ldap.Entry{entry})
	require.NoError(t, err)
	assert.Empty(t, filtered, "unsupported scope should exclude entry")
}

func TestFilterEntriesForRequestSizeLimit(t *testing.T) {
	entries := []*ldap.Entry{
		{DN: "cn=alice,cn=users,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{{Name: "objectClass", Values: []string{"user"}}}},
		{DN: "cn=bob,cn=users,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{{Name: "objectClass", Values: []string{"user"}}}},
	}
	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, SizeLimit: 1, Filter: "(objectClass=user)",
	}
	filtered, err := filterEntriesForRequest(req, entries)
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	assert.Equal(t, "cn=alice,cn=users,dc=example,dc=com", filtered[0].DN)
}

func TestBuildMemberOfValuesSkipsEmptyName(t *testing.T) {
	values := buildMemberOfValues([]string{"a", "", "b"}, "cn=groups,dc=example,dc=com")
	require.Len(t, values, 2)
	assert.Contains(t, values, "cn=a,cn=groups,dc=example,dc=com")
	assert.Contains(t, values, "cn=b,cn=groups,dc=example,dc=com")
}

func TestMemberOfValuesFromSetSkipsEmptyName(t *testing.T) {
	values := memberOfValuesFromSet(map[string]bool{"r1": true, "": true}, "ou=roles,dc=example,dc=com")
	require.Len(t, values, 1)
	assert.Equal(t, "cn=r1,ou=roles,dc=example,dc=com", values[0])
}

func TestSearchFilterCompileFails(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{{Username: "alice"}})
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
		Filter: "(invalid", Attributes: attributes9, Controls: []ldap.Control{},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.Error(t, err)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, res.ResultCode)
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
		Filter:     "(&(objectClass=user)(|(uid=z*)(sn=z*)(givenName=z*)(cn=z*)(displayname=z*)(userPrincipalName=z*)))",
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
		Filter:     "(&(objectClass=user)(|(uid=alice@*)(sn=alice@*)(givenName=alice@*)(cn=alice@*)(displayname=alice@*)(userPrincipalName=alice@*)))",
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
	uidAttr := entry.GetAttributeValue("uid")
	assert.Equal(t, "alice", cnAttr, "cn should match boundDN when entry DN is boundDN")
	assert.Equal(t, "alice", uidAttr, "uid should match boundDN when entry DN is boundDN")
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
		Filter:     "(&(objectClass=user)(|(uid=AL*)(sn=AL*)(givenName=AL*)(cn=AL*)(displayname=AL*)(userPrincipalName=AL*)))",
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
	var usersPathReceived string
	var compositePathReceived string
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			usersPathReceived = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{ID: "user-1", Username: "alice", FirstName: "Alice", LastName: "A", Email: "alice@example.com"},
			})
			return
		}
		if strings.Contains(r.URL.Path, "/role-mappings/realm/composite") && r.Method == "GET" {
			compositePathReceived = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]Role{
				{ID: "role-1", Name: "jellyfin-users"},
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

	require.Equal(t, "/admin/realms/test/users", usersPathReceived, "should fetch all users")
	require.Contains(t, compositePathReceived, "/users/user-1/role-mappings/realm/composite",
		"should get composite roles for each user to include inherited roles")
	require.Len(t, res.Entries, 1)
	assert.Equal(t, "cn=alice,cn=users,dc=example,dc=com", res.Entries[0].DN)
}

func TestSearchMemberOfRolesOneUserRoleMappingFailsContinues(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{ID: "u1", Username: "alice", FirstName: "A", LastName: "B", Email: "a@b.com"},
				{ID: "u2", Username: "bob", FirstName: "B", LastName: "C", Email: "b@c.com"},
			})
			return
		}
		if r.URL.Path == "/admin/realms/test/users/u1/role-mappings/realm/composite" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]Role{
				{ID: "r1", Name: "good-role"},
			})
			return
		}
		if r.URL.Path == "/admin/realms/test/users/u2/role-mappings/realm/composite" && r.Method == "GET" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	filter := "(|(memberOf=cn=bad-role,ou=roles,dc=example,dc=com)(memberOf=cn=good-role,ou=roles,dc=example,dc=com))"
	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: filter, Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1, "should return users from good-role despite one user role-mappings failing")
	assert.Equal(t, "cn=alice,cn=users,dc=example,dc=com", res.Entries[0].DN)
}

func TestSearchMemberOfRolesWithInheritedCompositeRoles(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{ID: "user-1", Username: "alice", FirstName: "Alice", LastName: "A", Email: "alice@example.com"},
				{ID: "user-2", Username: "bob", FirstName: "Bob", LastName: "B", Email: "bob@example.com"},
				{ID: "user-3", Username: "carol", FirstName: "Carol", LastName: "C", Email: "carol@example.com"},
			})
			return
		}
		if r.URL.Path == "/admin/realms/test/users/user-1/role-mappings/realm/composite" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]Role{
				{ID: "role-1", Name: "watch-jellyfin"},
				{ID: "role-2", Name: "default-roles-societycell"},
				{ID: "role-3", Name: "offline_access"},
			})
			return
		}
		if r.URL.Path == "/admin/realms/test/users/user-2/role-mappings/realm/composite" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]Role{
				{ID: "role-4", Name: "manage-jellyfin"},
				{ID: "role-5", Name: "watch-jellyfin"},
				{ID: "role-2", Name: "default-roles-societycell"},
			})
			return
		}
		if r.URL.Path == "/admin/realms/test/users/user-3/role-mappings/realm/composite" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]Role{
				{ID: "role-2", Name: "default-roles-societycell"},
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

	memberOfRolesFilter := "(|(memberOf=cn=watch-jellyfin,ou=roles,dc=example,dc=com)(memberOf=cn=manage-jellyfin,ou=roles,dc=example,dc=com))"
	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: memberOfRolesFilter, Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)

	require.Len(t, res.Entries, 2, "should return alice (watch-jellyfin inherited) and bob (both roles)")
	usernames := make([]string, len(res.Entries))
	for i, entry := range res.Entries {
		usernames[i] = entry.GetAttributeValue("cn")
	}
	assert.Contains(t, usernames, "alice")
	assert.Contains(t, usernames, "bob")
	assert.NotContains(t, usernames, "carol", "carol has no watch-jellyfin or manage-jellyfin role")

	bobEntry := res.Entries[0]
	if bobEntry.GetAttributeValue("cn") != "bob" {
		bobEntry = res.Entries[1]
	}
	memberOf := bobEntry.GetAttributeValues("memberOf")
	assert.Contains(t, memberOf, "cn=watch-jellyfin,ou=roles,dc=example,dc=com")
	assert.Contains(t, memberOf, "cn=manage-jellyfin,ou=roles,dc=example,dc=com")
}

func TestSearchMemberOfRolesWithRolesBaseDN(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{
				{ID: "user-1", Username: "admin", FirstName: "Admin", LastName: "User", Email: "admin@example.com"},
			})
			return
		}
		if r.URL.Path == "/admin/realms/test/users/user-1/role-mappings/realm/composite" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]Role{
				{ID: "role-1", Name: "manage-jellyfin"},
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

	adminFilter := "(memberOf=cn=manage-jellyfin,ou=roles,dc=example,dc=com)"
	req := ldap.SearchRequest{
		BaseDN: "ou=roles,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: adminFilter, Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1, "admin search with baseDN=ou=roles should work (Jellyfin admin filter)")
	assert.Equal(t, "cn=admin,cn=users,dc=example,dc=com", res.Entries[0].DN)
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
	exactFilter := "(&(objectClass=user)(|(uid=" + bindUser + ")(mail=" + bindUser + ")(cn=" + bindUser + ")))"
	req := ldap.SearchRequest{
		BaseDN: usersBase, Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter:     exactFilter,
		Attributes: []string{"uid", "userPrincipalName", "cn", "mail"},
		Controls:   []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1, "exact user lookup (Jellyfin-style) must return at least one entry for bound user %q", bindUser)
	assert.Equal(t, "cn="+bindUser+","+usersBase, res.Entries[0].DN)
}

func TestSearchUsersWithPictureAttribute(t *testing.T) {
	users := []User{
		{ID: "id1", Username: "alice", Email: "alice@example.com", FirstName: "Alice", LastName: "Smith",
			Attributes: map[string][]string{"picture": {"https://example.com/avatars/alice.jpg"}}},
		{ID: "id2", Username: "bob", Email: "bob@example.com", FirstName: "Bob", LastName: "Jones",
			Attributes: map[string][]string{}},
		{ID: "id3", Username: "charlie", Email: "charlie@example.com", FirstName: "Charlie", LastName: "Brown",
			Attributes: nil},
	}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(users)
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
		BaseDN:       "cn=users,dc=example,dc=com",
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       "(objectClass=user)",
		Attributes:   []string{"uid", "cn", "mail", "jpegPhoto"},
		Controls:     []ldap.Control{},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 3)

	aliceEntry := res.Entries[0]
	assert.Equal(t, "cn=alice,cn=users,dc=example,dc=com", aliceEntry.DN)
	jpegPhotoAttr := aliceEntry.GetAttributeValue("jpegPhoto")
	assert.Equal(t, "https://example.com/avatars/alice.jpg", jpegPhotoAttr, "alice should have jpegPhoto attribute from Keycloak picture")

	bobEntry := res.Entries[1]
	assert.Equal(t, "cn=bob,cn=users,dc=example,dc=com", bobEntry.DN)
	bobJpegPhoto := bobEntry.GetAttributeValue("jpegPhoto")
	assert.Empty(t, bobJpegPhoto, "bob should not have jpegPhoto attribute (empty attributes map)")

	charlieEntry := res.Entries[2]
	assert.Equal(t, "cn=charlie,cn=users,dc=example,dc=com", charlieEntry.DN)
	charlieJpegPhoto := charlieEntry.GetAttributeValue("jpegPhoto")
	assert.Empty(t, charlieJpegPhoto, "charlie should not have jpegPhoto attribute (nil attributes)")
}

func TestSearchUserBoundWithPicture(t *testing.T) {
	userinfoResp := map[string]interface{}{
		"sub":                "sub-alice",
		"preferred_username": "alice",
		"given_name":         "Alice",
		"family_name":        "Smith",
		"email":              "alice@example.com",
		"picture":            "https://example.com/avatars/alice.jpg",
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

	bindDN := "cn=alice,cn=users,dc=example,dc=com"
	code, _ := h.Bind(bindDN, "pass", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	req := ldap.SearchRequest{
		BaseDN:       bindDN,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=user)",
		Attributes:   []string{"uid", "cn", "mail", "jpegPhoto"},
		Controls:     []ldap.Control{},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1)

	entry := res.Entries[0]
	assert.Equal(t, bindDN, entry.DN)
	jpegPhotoAttr := entry.GetAttributeValue("jpegPhoto")
	assert.Equal(t, "https://example.com/avatars/alice.jpg", jpegPhotoAttr, "user-bound entry should have jpegPhoto from userinfo picture")
}
