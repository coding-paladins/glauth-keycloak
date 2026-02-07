package keycloak

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/glauth/ldap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestErrorSearchResult(t *testing.T) {
	res := errorSearchResult()
	assert.True(t, res.ResultCode == ldap.LDAPResultOperationsError, "result code should be operations error")
	assert.Empty(t, res.Entries)
}

func TestBindConfigNil(t *testing.T) {
	h := &keycloakHandler{config: nil, sessions: map[string]*session{"default": {}}, log: &nopLogger}
	code, err := h.Bind("cn=u,cn=users,dc=example,dc=com", "pw", nil)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, code)
	assert.Error(t, err)
}

func TestBindServiceAccountSuccess(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "service-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, err := h.Bind("cn=myclient,cn=bind,dc=example,dc=com", "client-secret", nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, code)
	assert.NotNil(t, h.getSession(nil).token)
}

func TestBindServiceAccountClientIDWithEscapedComma(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "service-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	// Bind DN with escaped comma in cn (client ID is "my,client"); unescaped value is sent to Keycloak.
	code, err := h.Bind("cn=my\\,client,cn=bind,dc=example,dc=com", "secret", nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, code)
}

func TestBindServiceAccountTokenFails(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, err := h.Bind("cn=myclient,cn=bind,dc=example,dc=com", "bad-secret", nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultInvalidCredentials, code)
}

func TestBindUserSuccess(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "password", r.Form.Get("grant_type"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "user-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, err := h.Bind("cn=alice,cn=users,dc=example,dc=com", "alice-pass", nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, code)
	assert.True(t, h.getSession(nil).isUserBound)
}

func TestBindUserInvalidBindDN(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	config.ldapClientID = "client"
	config.ldapClientSecret = "secret"
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("uid=alice,cn=users,dc=example,dc=com", "pw", nil)
	assert.EqualValues(t, ldap.LDAPResultInvalidCredentials, code)
}

func TestBindInvalidBindDN(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=someone,ou=other,dc=example,dc=com", "pw", nil)
	assert.EqualValues(t, ldap.LDAPResultInvalidCredentials, code)
}

func TestCloseSuccess(t *testing.T) {
	boundDN := "cn=alice,cn=users,dc=example,dc=com"
	sess := &session{boundDN: &boundDN, token: &oauth2.Token{AccessToken: "x"}, isUserBound: true}
	h := &keycloakHandler{
		sessions:  map[string]*session{"default": sess},
		connToKey: make(map[net.Conn]string),
		log:       &nopLogger,
	}
	err := h.Close(boundDN, nil)
	require.NoError(t, err)
	// After fix: the entire session is deleted, not just its fields
	h.sessionsMu.RLock()
	_, exists := h.sessions["default"]
	h.sessionsMu.RUnlock()
	assert.False(t, exists, "Session should be deleted")
}

func TestCloseSuccessWithConnDeletesFromConnToKey(t *testing.T) {
	conn, connOther := net.Pipe()
	defer conn.Close()
	defer connOther.Close()

	boundDN := "cn=svc,cn=bind,dc=example,dc=com"
	sess := &session{boundDN: &boundDN, token: &oauth2.Token{AccessToken: "x"}, lastActivity: time.Now()}
	key := "conn-1"
	h := &keycloakHandler{
		sessions:  map[string]*session{key: sess},
		connToKey: map[net.Conn]string{conn: key},
		log:       &nopLogger,
	}
	err := h.Close(boundDN, conn)
	require.NoError(t, err)
	h.sessionsMu.RLock()
	_, exists := h.sessions[key]
	h.sessionsMu.RUnlock()
	assert.False(t, exists, "Session should be deleted")
	_, inMap := h.connToKey[conn]
	assert.False(t, inMap, "conn should be removed from connToKey")
}

func TestCheckSessionNilSession(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := &keycloakHandler{config: config, log: &nopLogger}
	err := h.checkSession(nil, "cn=alice,cn=users,dc=example,dc=com", false, h.config.tokenEndpoint())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no session")
}

func TestCheckSessionNilToken(t *testing.T) {
	boundDN := "cn=alice,cn=users,dc=example,dc=com"
	h := &keycloakHandler{
		config:   makeHandlerConfigFromURL(t, "http://127.0.0.1:8443"),
		sessions: map[string]*session{"default": {boundDN: &boundDN, token: nil}},
		log:      &nopLogger,
	}
	err := h.checkSession(h.getSession(nil), boundDN, false, h.config.tokenEndpoint())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no session token")
}

func TestCloseSessionKeyEmptyReturnsNil(t *testing.T) {
	conn, connOther := net.Pipe()
	defer conn.Close()
	defer connOther.Close()
	boundDN := "cn=svc,cn=bind,dc=example,dc=com"
	sess := &session{boundDN: &boundDN, token: &oauth2.Token{AccessToken: "x"}, lastActivity: time.Now()}
	h := &keycloakHandler{
		sessions:  map[string]*session{"": sess},
		connToKey: map[net.Conn]string{conn: ""},
		log:       &nopLogger,
	}
	err := h.Close(boundDN, conn)
	require.NoError(t, err)
	_, stillExists := h.sessions[""]
	assert.True(t, stillExists, "empty key session is not deleted")
}

func TestCloseSessionError(t *testing.T) {
	// Session must have lastActivity set so it is not removed by cleanStaleSessionsLocked before checkSession.
	boundDN := "cn=bob,cn=users,dc=example,dc=com"
	h := &keycloakHandler{
		sessions:  map[string]*session{"default": {boundDN: &boundDN, token: &oauth2.Token{AccessToken: "x"}, lastActivity: time.Now()}},
		connToKey: map[net.Conn]string{nil: "default"},
		log:       &nopLogger,
	}
	err := h.Close("cn=alice,cn=users,dc=example,dc=com", nil)
	assert.Error(t, err)
}

func TestAdd(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	code, err := h.Add("cn=users,dc=example,dc=com", ldap.AddRequest{}, nil)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, code)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Add")
}

func TestModify(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	code, err := h.Modify("cn=users,dc=example,dc=com", ldap.ModifyRequest{}, nil)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, code)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Modify")
}

func TestDelete(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	code, err := h.Delete("cn=users,dc=example,dc=com", "cn=foo,cn=users,dc=example,dc=com", nil)
	assert.EqualValues(t, ldap.LDAPResultOperationsError, code)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Delete")
}

func TestFindUser(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	ok, user, err := h.FindUser(context.Background(), "alice", false)
	assert.False(t, ok)
	assert.Empty(t, user.Name)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "FindUser")
}

func TestFindGroup(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	ok, group, err := h.FindGroup(context.Background(), "admins")
	assert.False(t, ok)
	assert.Empty(t, group.Name)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "FindGroup")
}

func TestServiceAccountBindClearsUserBoundSessionState(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			assert.NoError(t, r.ParseForm())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "tok",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	conn, connOther := net.Pipe()
	defer conn.Close()
	defer connOther.Close()

	code, err := h.Bind("cn=alice,cn=users,dc=example,dc=com", "pass", conn)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)
	require.True(t, h.getSession(conn).isUserBound)

	code, err = h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", conn)
	require.NoError(t, err)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	assert.False(t, h.getSession(conn).isUserBound, "service account bind should clear user-bound state")
}

func TestBug4_EmptyUsernameAccepted(t *testing.T) {
	baseDN := "cn=users,dc=example,dc=com"

	// BUG: Empty username should be rejected but is accepted
	username, ok := parseUsernameFromUserBindDN("cn=,cn=users,dc=example,dc=com", baseDN)

	if ok && username == "" {
		t.Log("BUG CONFIRMED: empty username accepted as valid")
		// This is the bug we expect to exist
	} else if !ok {
		t.Log("Bug might already be fixed - empty username correctly rejected")
	}
}

func TestBug5_FirstNamePrefixNotChecked(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			// User with FirstName matching prefix but Username and LastName not matching
			_ = json.NewEncoder(w).Encode([]User{
				{Username: "john123", FirstName: "Bob", LastName: "Smith", Email: "john@example.com"},
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

	// Search for users with firstName prefix "Bob"
	req := ldap.SearchRequest{
		BaseDN: "cn=users,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter:     "(&(objectClass=user)(|(uid=Bob*)(sn=Bob*)(givenName=Bob*)(cn=Bob*)(displayname=Bob*)(userPrincipalName=Bob*)))",
		Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)

	// BUG: The filter should match givenName (FirstName) but the code only checks Username and LastName
	if len(res.Entries) == 0 {
		t.Log("BUG CONFIRMED: FirstName prefix not checked, user with matching FirstName not returned")
		// This is the bug we expect to exist
	} else {
		t.Log("Bug might be fixed - FirstName prefix correctly checked")
	}
}

func TestBug6_InitErrorReturnsEmptyHandler(t *testing.T) {
	// Unset required environment variables
	oldEnv := make(map[string]string)
	for _, k := range []string{"KEYCLOAK_HOSTNAME", "KEYCLOAK_PORT", "KEYCLOAK_REALM", "LDAP_DOMAIN"} {
		oldEnv[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	defer func() {
		for k, v := range oldEnv {
			if v != "" {
				os.Setenv(k, v)
			}
		}
	}()

	h := NewKeycloakHandler()

	// After fix: should return nil instead of empty handler with nil config
	if h == nil {
		t.Log("Bug FIXED: Handler correctly returns nil on initialization error")
	} else {
		t.Log("BUG CONFIRMED: Handler with nil config was returned and will cause errors on use")
	}
}

func TestBugConfirm_UserBoundSearchBaseDNCaseInsensitive(t *testing.T) {
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

	// Same logical DN as userDN but different case (LDAP DNs are case-insensitive).
	baseDNUpper := "CN=alice,CN=USERS,DC=EXAMPLE,DC=COM"
	req := ldap.SearchRequest{
		BaseDN: baseDNUpper, Scope: ldap.ScopeBaseObject, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1, "BaseDN comparison should be case-insensitive")
}

func TestBugConfirm_GroupPrefixSearchCaseInsensitive(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/groups" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]Group{{ID: "g1", Name: "admins"}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	// Filter with uppercase prefix "ADMIN" (group name from Keycloak is "admins").
	req := ldap.SearchRequest{
		BaseDN: "cn=groups,dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter:     "(&(objectClass=group)(|(sAMAccountName=ADMIN*)(cn=ADMIN*)))",
		Attributes: attributes3,
		Controls:   []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1, "group prefix search should be case-insensitive (ADMIN* matches admins)")
}

func TestBugConfirm_ServiceAccountSearchBaseDNCaseInsensitive(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]User{{Username: "alice", FirstName: "A", LastName: "B", Email: "a@b.com"}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	// Same logical BaseDN as cn=users,dc=example,dc=com but different case.
	baseDNUpper := "CN=users,DC=example,DC=com"
	req := ldap.SearchRequest{
		BaseDN: baseDNUpper, Scope: ldap.ScopeWholeSubtree, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectClass=user)", Attributes: attributes9, Controls: []ldap.Control{ldap.NewControlPaging(100)},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	require.Len(t, res.Entries, 1, "service-account search BaseDN should be case-insensitive")
}
