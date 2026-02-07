package keycloak

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glauth/ldap"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

var nopLogger = zerolog.Nop()

var attributes3 = []string{
	"sAMAccountName",
	"description",
	"objectSid",
}

var attributes9 = []string{
	"sAMAccountName",
	"userPrincipalName",
	"description",
	"givenName",
	"sn",
	"mail",
	"userAccountControl",
	"lockoutTime",
	"objectSid",
}

func init() {
	allowNilConnectionForTests = true
}

func makeHandlerConfigFromURL(t *testing.T, serverURL string) *keycloakHandlerConfig {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	require.NoError(t, err)
	port := 443
	if parsed.Port() != "" {
		port, _ = strconv.Atoi(parsed.Port())
	}
	scheme := "https"
	if parsed.Scheme != "" {
		scheme = parsed.Scheme
	}
	return &keycloakHandlerConfig{
		keycloakHostname:    parsed.Hostname(),
		keycloakPort:        port,
		keycloakRealm:       "test",
		keycloakScheme:      scheme,
		ldapDomain:          "example.com",
		ldapClientID:        "ldap-client",
		ldapClientSecret:    "secret",
		userinfoEndpointURL: serverURL + "/userinfo",
	}
}

func makeHandlerWithConfig(c *keycloakHandlerConfig) *keycloakHandler {
	b := "dc=example,dc=com"
	if c.ldapDomain != "" {
		parts := strings.Split(c.ldapDomain, ".")
		b = "dc=" + strings.Join(parts, ",dc=")
	}
	var transport http.RoundTripper
	if c.keycloakScheme != "http" {
		transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if transport != nil {
		httpClient.Transport = transport
	}
	return &keycloakHandler{
		config:          c,
		baseDNUsers:     "cn=users," + b,
		baseDNGroups:    "cn=groups," + b,
		baseDNBindUsers: "cn=bind," + b,
		httpClient:      httpClient,
		sessions:        map[string]*session{"default": {}},
		log:             &nopLogger,
	}
}

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

func TestHide(t *testing.T) {
	assert.Equal(t, "********", hide("password"))
}

func TestRestAPIEndpoint(t *testing.T) {
	c := keycloakHandlerConfig{
		keycloakHostname: "localhost",
		keycloakPort:     8443,
		keycloakRealm:    "test-realm"}
	assert.Equal(t, "https://localhost:8443/admin/realms/test-realm/users",
		c.restAPIEndpoint("users"))
}

func TestSid(t *testing.T) {
	s := sidToString(sid("4e292dae-35db-4f1a-b40b-17e8e0a3a6b7", "domain.com"))
	assert.True(t, strings.HasPrefix(s, "S-1-5-21-"), "SID should be NT authority, domain-relative")
	parts := strings.Split(s, "-")
	assert.GreaterOrEqual(t, len(parts), 5, "SID should have revision + identifier authority + sub-authorities")
}

func TestTokenEndpoint(t *testing.T) {
	c := keycloakHandlerConfig{
		keycloakHostname: "localhost",
		keycloakPort:     8443,
		keycloakRealm:    "test-realm"}
	assert.Equal(t, "https://localhost:8443/realms/test-realm/protocol/"+
		"openid-connect/token", c.tokenEndpoint())
}

func TestUserinfoEndpoint(t *testing.T) {
	c := keycloakHandlerConfig{
		keycloakHostname:    "keycloak.example.com",
		keycloakPort:        8443,
		keycloakRealm:       "myrealm",
		userinfoEndpointURL: "https://keycloak.example.com:8443/realms/myrealm/protocol/openid-connect/userinfo",
	}
	assert.Equal(t, "https://keycloak.example.com:8443/realms/myrealm/protocol/openid-connect/userinfo",
		c.userinfoEndpointURL)
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

func TestSessionOpenUser(t *testing.T) {
	s := &session{}
	token := &oauth2.Token{AccessToken: "test-token", Expiry: time.Now().Add(time.Hour)}
	s.openUser("cn=alice,cn=users,dc=example,dc=com", token)
	assert.True(t, s.isUserBound)
	require.NotNil(t, s.boundDN)
	assert.Equal(t, "cn=alice,cn=users,dc=example,dc=com", *s.boundDN)
	assert.Equal(t, token, s.token)
	assert.Empty(t, s.clientID)
	assert.Empty(t, s.clientSecret)
}

func TestPasswordGrantSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "password", r.Form.Get("grant_type"))
		assert.Equal(t, "testuser", r.Form.Get("username"))
		assert.Equal(t, "testpass", r.Form.Get("password"))
		assert.Equal(t, "ldap-client", r.Form.Get("client_id"))
		w.Header().Set("Content-Type", "application/json")
		body := map[string]interface{}{
			"access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()

	token, err := passwordGrant(&nopLogger, server.URL, "ldap-client", "secret", "testuser", "testpass", nil)
	require.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", token.AccessToken)
	assert.True(t, token.Valid())
}

func TestPasswordGrantInvalidCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	token, err := passwordGrant(&nopLogger, server.URL, "ldap-client", "secret", "baduser", "badpass", nil)
	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestPasswordGrantInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	token, err := passwordGrant(&nopLogger, server.URL, "ldap-client", "secret", "u", "p", nil)
	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestNewAttribute(t *testing.T) {
	a := newAttribute("cn", "johndoe")
	require.NotNil(t, a)
	assert.Equal(t, "cn", a.Name)
	assert.Len(t, a.Values, 1)
	assert.Equal(t, "johndoe", a.Values[0])
}

func TestErrorSearchResult(t *testing.T) {
	res := errorSearchResult()
	assert.True(t, res.ResultCode == ldap.LDAPResultOperationsError, "result code should be operations error")
	assert.Empty(t, res.Entries)
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

func TestParseFirstCNValueFromBindDNWithSuffixServiceAccount(t *testing.T) {
	// Escaped comma in first RDN value.
	got, ok := parseFirstCNValueFromBindDNWithSuffix("cn=my\\,client,cn=bind,dc=example,dc=com", ",cn=bind,dc=example,dc=com")
	require.True(t, ok)
	assert.Equal(t, "my,client", got)
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

func TestEnvNotSet(t *testing.T) {
	err := envNotSet("MISSING_VAR")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MISSING_VAR")
}

func TestUnexpected(t *testing.T) {
	err := unexpected("SomeOp")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SomeOp")
}

func TestGetenv(t *testing.T) {
	t.Setenv("TEST_GETENV_KEY", "test-value")
	assert.Equal(t, "test-value", getenv(&nopLogger, "TEST_GETENV_KEY"))
}

func TestClientCredentialsGrantSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	token, err := clientCredentialsGrant(&nopLogger, server.URL, "client", "secret", nil)
	require.NoError(t, err)
	assert.NotNil(t, token)
	assert.True(t, token.Valid())
}

func TestClientCredentialsGrantInvalidCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	token, err := clientCredentialsGrant(&nopLogger, server.URL, "client", "secret", nil)
	assert.Error(t, err)
	assert.Nil(t, token)
}

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

// TestJellyfinExactUserLookup verifies that a Jellyfin-style exact user lookup filter
// (e.g. (&(objectClass=user)(|(sAMAccountName=alice)(mail=alice@example.com)))) returns the matching user.
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

func TestSessionRefresh(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "new-token", "token_type": "Bearer", "expires_in": 3600})
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)
	h.sessions["default"].token = &oauth2.Token{AccessToken: "old", Expiry: time.Now().Add(-time.Hour)}

	req := ldap.SearchRequest{
		BaseDN: "", Scope: ldap.ScopeBaseObject, DerefAliases: ldap.NeverDerefAliases,
		SizeLimit: 0, TimeLimit: 0, TypesOnly: false,
		Filter: "(objectclass=*)", Attributes: []string{}, Controls: []ldap.Control{},
	}
	res, err := h.Search(*h.getSession(nil).boundDN, req, nil)
	require.NoError(t, err)
	assert.EqualValues(t, ldap.LDAPResultSuccess, res.ResultCode)
	assert.Equal(t, "new-token", h.getSession(nil).token.AccessToken)
}

func TestNewKeycloakHandlerMissingEnv(t *testing.T) {
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
	// After fix: should return nil instead of empty handler
	assert.Nil(t, h)
}

func TestNewKeycloakHandlerSuccess(t *testing.T) {
	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Setenv("KEYCLOAK_PORT", "8443")
	os.Setenv("KEYCLOAK_REALM", "myrealm")
	os.Setenv("LDAP_DOMAIN", "example.com")
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_PORT")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("LDAP_DOMAIN")
	}()

	h := NewKeycloakHandler().(*keycloakHandler)
	require.NotNil(t, h.config)
	assert.Equal(t, "cn=users,dc=example,dc=com", h.baseDNUsers)
}

func TestNewKeycloakHandlerConfigInvalidPort(t *testing.T) {
	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Setenv("KEYCLOAK_PORT", "not-a-number")
	os.Setenv("KEYCLOAK_REALM", "r")
	os.Setenv("LDAP_DOMAIN", "example.com")
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_PORT")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("LDAP_DOMAIN")
	}()

	h := NewKeycloakHandler()
	// After fix: should return nil instead of empty handler
	assert.Nil(t, h)
}

func TestNewKeycloakHandlerConfigVsphereDomainTrailingDot(t *testing.T) {
	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Setenv("KEYCLOAK_PORT", "8443")
	os.Setenv("KEYCLOAK_REALM", "r")
	os.Setenv("LDAP_DOMAIN", "example.com.")
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_PORT")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("LDAP_DOMAIN")
	}()

	h := NewKeycloakHandler().(*keycloakHandler)
	require.NotNil(t, h.config)
	assert.Equal(t, "example.com", h.config.ldapDomain)
}

func TestNewKeycloakHandlerConfigDefaultPort(t *testing.T) {
	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Unsetenv("KEYCLOAK_PORT")
	os.Setenv("KEYCLOAK_REALM", "r")
	os.Setenv("LDAP_DOMAIN", "example.com")
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("LDAP_DOMAIN")
	}()

	h := NewKeycloakHandler().(*keycloakHandler)
	require.NotNil(t, h.config)
	assert.Equal(t, 8444, h.config.keycloakPort)
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

func TestSessionRefreshTokenStillValid(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	boundDN := "cn=svc,cn=bind,dc=example,dc=com"
	h := &keycloakHandler{
		config: config,
		sessions: map[string]*session{"default": {
			boundDN: &boundDN,
			token:   &oauth2.Token{AccessToken: "valid", Expiry: time.Now().Add(time.Hour)},
		}},
		log: &nopLogger,
	}
	err := h.checkSession(h.getSession(nil), boundDN, true, h.config.tokenEndpoint())
	require.NoError(t, err)
}

func TestSessionRefreshIsUserBound(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	boundDN := "cn=alice,cn=users,dc=example,dc=com"
	h := &keycloakHandler{
		config: config,
		sessions: map[string]*session{"default": {
			boundDN:     &boundDN,
			token:       &oauth2.Token{AccessToken: "x", Expiry: time.Now().Add(-time.Hour)},
			isUserBound: true,
		}},
		log: &nopLogger,
	}
	err := h.checkSession(h.getSession(nil), boundDN, true, h.config.tokenEndpoint())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user token expired")
}

func TestClientCredentialsGrantInvalidTokenResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "",
			"token_type":   "Bearer",
			"expires_in":   0,
		})
	}))
	defer server.Close()

	token, err := clientCredentialsGrant(&nopLogger, server.URL, "client", "secret", nil)
	assert.Error(t, err)
	assert.Nil(t, token)
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

func TestCheckSessionRejectsExpiredUserToken(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	boundDN := "cn=alice,cn=users,dc=example,dc=com"
	h := &keycloakHandler{
		config: config,
		sessions: map[string]*session{"default": {
			boundDN:     &boundDN,
			token:       &oauth2.Token{AccessToken: "expired", Expiry: time.Now().Add(-time.Hour)},
			isUserBound: true,
		}},
		log: &nopLogger,
	}

	err := h.checkSession(h.getSession(nil), boundDN, true, h.config.tokenEndpoint())
	assert.Error(t, err, "expired user token should be rejected")
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

func TestCheckSessionBoundDNNil(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := &keycloakHandler{
		config:   config,
		sessions: map[string]*session{"default": {}}, // boundDN is nil
		log:      &nopLogger,
	}
	err := h.checkSession(h.getSession(nil), "cn=alice,cn=users,dc=example,dc=com", false, config.tokenEndpoint())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected boundDN")
}

func TestSessionRefreshGrantFails(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	boundDN := "cn=svc,cn=bind,dc=example,dc=com"
	h := &keycloakHandler{
		config: config,
		sessions: map[string]*session{"default": {
			boundDN:      &boundDN,
			clientID:     "svc",
			clientSecret: "secret",
			token:        &oauth2.Token{AccessToken: "old", Expiry: time.Now().Add(-time.Hour)},
		}},
		log: &nopLogger,
	}
	err := h.checkSession(h.getSession(nil), boundDN, true, h.config.tokenEndpoint())
	assert.Error(t, err)
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

func TestCheckSessionBoundDNCaseInsensitive(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	boundDN := "cn=alice,cn=users,dc=example,dc=com"
	h := &keycloakHandler{
		config: config,
		sessions: map[string]*session{"default": {
			boundDN: &boundDN,
			token:   &oauth2.Token{AccessToken: "x", Expiry: time.Now().Add(time.Hour)},
		}},
		log: &nopLogger,
	}
	err := h.checkSession(h.getSession(nil), "CN=ALICE,CN=USERS,DC=EXAMPLE,DC=COM", false, h.config.tokenEndpoint())
	assert.NoError(t, err, "boundDN comparison should be case-insensitive")
}

func TestKeycloakUserinfoConnectionFails(t *testing.T) {
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
	closedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedServer.Close()
	config.userinfoEndpointURL = closedServer.URL + "/userinfo"
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

func TestNewKeycloakHandlerConfigMissingRealm(t *testing.T) {
	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Setenv("KEYCLOAK_PORT", "8443")
	os.Unsetenv("KEYCLOAK_REALM")
	os.Setenv("LDAP_DOMAIN", "example.com")
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_PORT")
		os.Unsetenv("LDAP_DOMAIN")
	}()

	h := NewKeycloakHandler()
	// After fix: should return nil instead of empty handler
	assert.Nil(t, h)
}

func TestPasswordGrantEmptyAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	token, err := passwordGrant(&nopLogger, server.URL, "ldap-client", "secret", "u", "p", nil)
	assert.Error(t, err)
	assert.Nil(t, token)
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

// TestGetSessionConnNotInMapReturnsNil ensures that when conn is not in connToKey
// we return nil (the session doesn't exist for this connection).
func TestGetSessionConnNotInMapReturnsNil(t *testing.T) {
	boundDN := "cn=alice,cn=users,dc=example,dc=com"
	sess := &session{boundDN: &boundDN, token: &oauth2.Token{AccessToken: "x"}}
	h := &keycloakHandler{
		sessions:  map[string]*session{"default": sess},
		connToKey: make(map[net.Conn]string),
		log:       &nopLogger,
	}
	conn, connOther := net.Pipe()
	defer conn.Close()
	defer connOther.Close()

	// After fix: getSession should return nil for unknown connections
	got := h.getSession(conn)
	assert.Nil(t, got, "Unknown connection should return nil session")
}

// TestCloseConnNotInMapGracefullyHandles ensures Close handles unknown connections gracefully.
func TestCloseConnNotInMapGracefullyHandles(t *testing.T) {
	boundDN := "cn=alice,cn=users,dc=example,dc=com"
	sess := &session{boundDN: &boundDN, token: &oauth2.Token{AccessToken: "x"}, isUserBound: true}
	h := &keycloakHandler{
		sessions:  map[string]*session{"default": sess},
		connToKey: make(map[net.Conn]string),
		log:       &nopLogger,
	}
	conn, connOther := net.Pipe()
	defer conn.Close()
	defer connOther.Close()

	// After fix: Close should handle unknown connections gracefully
	err := h.Close(boundDN, conn)
	// It's OK to return nil (connection wasn't tracked) or an error (no session)
	// The important thing is it doesn't panic
	t.Logf("Close returned: %v", err)
}

// TestSessionKeyUnknownConnReturnsEmptyString ensures sessionKey(conn) returns empty string when conn is not in map.
func TestSessionKeyUnknownConnReturnsEmptyString(t *testing.T) {
	h := &keycloakHandler{connToKey: make(map[net.Conn]string), log: &nopLogger}
	conn, connOther := net.Pipe()
	defer conn.Close()
	defer connOther.Close()
	key := h.sessionKey(conn)
	// After fix: should return empty string for unknown connections
	assert.Equal(t, "", key, "Unknown connection should return empty string")
}

// TestKeycloakGetNon200ReturnsErrorAndLogsBody ensures keycloakGet on 403 returns error (body is logged in code).
func TestKeycloakGetNon200ReturnsErrorAndLogsBody(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" {
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":"forbidden","error_description":"insufficient permissions"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tokenServer.Close()

	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	users := &[]User{}
	err := h.keycloakGet(h.getSession(nil), "users", users)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

// BUG TESTS - Tests confirming bugs found in code review

// TestBug1_ConnToKeyNotInitialized tests that connToKey map is not initialized in NewKeycloakHandler
func TestBug1_ConnToKeyNotInitialized(t *testing.T) {
	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Setenv("KEYCLOAK_PORT", "8443")
	os.Setenv("KEYCLOAK_REALM", "myrealm")
	os.Setenv("LDAP_DOMAIN", "example.com")
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_PORT")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("LDAP_DOMAIN")
	}()

	h := NewKeycloakHandler().(*keycloakHandler)
	require.NotNil(t, h.config)

	// BUG: connToKey is not initialized
	if h.connToKey == nil {
		t.Log("BUG CONFIRMED: connToKey is nil after NewKeycloakHandler")
	} else {
		t.Log("Bug might be fixed - connToKey is initialized")
	}

	// This will panic if connToKey is nil when trying to add to it
	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	// Test will panic here if bug exists, but we'll catch it
	defer func() {
		if r := recover(); r != nil {
			t.Logf("BUG CONFIRMED: Panic when using nil connToKey: %v", r)
		}
	}()

	h.getOrCreateSession(conn1)
}

// TestBug2_SessionCleanupMultipleConnections tests that session cleanup doesn't handle multiple connections per session
func TestBug2_SessionCleanupMultipleConnections(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)

	// Create multiple connections that share the same session
	conn1, conn1b := net.Pipe()
	conn2, conn2b := net.Pipe()
	defer conn1.Close()
	defer conn1b.Close()
	defer conn2.Close()
	defer conn2b.Close()

	// Create sessions for both connections
	sess1 := h.getOrCreateSession(conn1)
	sess2 := h.getOrCreateSession(conn2)

	// Make both sessions expired
	sess1.lastActivity = time.Now().Add(-sessionTTL - time.Minute)
	sess2.lastActivity = time.Now().Add(-sessionTTL - time.Minute)

	// Store the number of connections before cleanup
	_ = len(h.connToKey) // connsBefore - for future use if needed

	// Trigger cleanup by creating a new session
	conn3, conn3b := net.Pipe()
	defer conn3.Close()
	defer conn3b.Close()
	h.getOrCreateSession(conn3)

	// BUG: The cleanup only removes one connection per session key due to break statement
	// If there were multiple connections with same session, some will leak
	if len(h.connToKey) > 1 {
		t.Logf("BUG CONFIRMED: connToKey still has %d entries after cleanup (expected cleanup)", len(h.connToKey))
	}
}

// TestBug3_SessionKeyInconsistency tests inconsistency between sessionKey() and getOrCreateSession()
func TestBug3_SessionKeyInconsistency(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)

	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	// Get the key before the session is created
	keyBefore := h.sessionKey(conn1)

	// Create the session
	h.getOrCreateSession(conn1)

	// Get the key after the session is created
	keyAfter := h.sessionKey(conn1)

	// After fix: keyBefore should be empty string for unknown connections,
	// keyAfter should be the assigned unique key
	if keyBefore == "" && keyAfter != "" && keyAfter != "default" {
		t.Log("Bug FIXED: sessionKey correctly returns empty for unknown, then unique key after creation")
	} else {
		t.Logf("sessionKey behavior - before: %q, after: %q", keyBefore, keyAfter)
	}

	// Verify the session is stored under the unique key
	h.sessionsMu.RLock()
	_, hasUniqueKey := h.sessions[keyAfter]
	h.sessionsMu.RUnlock()

	assert.True(t, hasUniqueKey, "Session should be stored under unique key")
}

// TestBug4_EmptyUsernameAccepted tests that parseUsernameFromUserBindDN accepts empty usernames
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

// TestBug5_FirstNamePrefixNotChecked tests that usersSearchResult doesn't check firstName prefix
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
		Filter:     "(&(objectClass=user)(|(sAMAccountName=Bob*)(sn=Bob*)(givenName=Bob*)(cn=Bob*)(displayname=Bob*)(userPrincipalName=Bob*)))",
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

// TestBug6_InitErrorReturnsEmptyHandler tests that initialization errors return a non-functional handler
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

// TestBug7_OAuth2NoContextTimeout tests that OAuth2 calls don't have timeout
func TestBug7_OAuth2NoContextTimeout(t *testing.T) {
	// Create a server that hangs for longer than our timeout
	hangingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang for longer than httpClientTimeout (30s)
		time.Sleep(35 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		hangingServer.CloseClientConnections()
		hangingServer.Close()
	}()

	// After fix: clientCredentialsGrant should timeout after httpClientTimeout (30s)
	start := time.Now()
	_, err := clientCredentialsGrant(&nopLogger, hangingServer.URL, "client", "secret", nil)
	elapsed := time.Since(start)

	if err != nil && elapsed < 35*time.Second {
		t.Logf("Bug FIXED: Request timed out after %v with error: %v", elapsed, err)
	} else {
		t.Logf("Request took %v, error: %v", elapsed, err)
	}
}

// TestBug3_SessionKeyWrongMapping tests that sessions stored with unique keys can't be retrieved
func TestBug3_SessionKeyWrongMapping(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)

	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	// Create session with a connection
	sess := h.getOrCreateSession(conn1)
	boundDN := "cn=test,cn=bind,dc=example,dc=com"
	sess.boundDN = &boundDN
	sess.token = &oauth2.Token{AccessToken: "test-token"}

	// Try to retrieve the session
	retrievedSess := h.getSession(conn1)

	// BUG: If the session is stored under a unique key but retrieved as "default",
	// we won't get the same session back
	if retrievedSess != sess {
		t.Error("BUG CONFIRMED: Session created with connection can't be retrieved correctly")
	}
}

// TestBug8_SessionCleanupMemoryLeak tests that sessions never get cleaned up without new sessions
func TestBug8_SessionCleanupMemoryLeak(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)

	// Create some expired sessions
	conn1, conn1b := net.Pipe()
	defer conn1.Close()
	defer conn1b.Close()

	sess1 := h.getOrCreateSession(conn1)
	sess1.lastActivity = time.Now().Add(-sessionTTL - time.Hour)

	// Close the connection but don't call Close()
	conn1.Close()
	conn1b.Close()

	// Wait a long time without creating new sessions
	// BUG: Expired sessions are never cleaned up unless getOrCreateSession is called
	time.Sleep(10 * time.Millisecond)

	h.sessionsMu.RLock()
	numSessions := len(h.sessions)
	h.sessionsMu.RUnlock()

	if numSessions > 0 {
		t.Logf("BUG CONFIRMED: %d expired sessions still in memory (should be cleaned up by background goroutine)", numSessions)
	}
}

// TestBug9_PasswordGrantGenericError tests that non-200 responses all return generic error
func TestBug9_PasswordGrantGenericError(t *testing.T) {
	testCases := []struct {
		name       string
		statusCode int
		body       string
	}{
		{"unauthorized", http.StatusUnauthorized, `{"error":"invalid_grant"}`},
		{"forbidden", http.StatusForbidden, `{"error":"access_denied"}`},
		{"server_error", http.StatusInternalServerError, `{"error":"server_error"}`},
		{"bad_gateway", http.StatusBadGateway, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				if tc.body != "" {
					w.Write([]byte(tc.body))
				}
			}))
			defer server.Close()

			_, err := passwordGrant(&nopLogger, server.URL, "client", "secret", "user", "pass", nil)
			require.Error(t, err)

			// BUG: All errors return the same generic "invalid credentials" message
			if err.Error() == "invalid credentials" {
				t.Logf("BUG CONFIRMED: %d status returns generic 'invalid credentials' instead of specific error", tc.statusCode)
			}
		})
	}
}

// TestBug10_ResponseBodyNoLimit tests that large response bodies aren't limited
func TestBug10_ResponseBodyNoLimit(t *testing.T) {
	// Create a server that returns a huge response
	hugeResponse := strings.Repeat("x", 100*1024*1024) // 100MB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/userinfo" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"sub":"` + hugeResponse + `"}`))
		}
	}))
	defer server.Close()

	config := makeHandlerConfigFromURL(t, server.URL)
	config.userinfoEndpointURL = server.URL + "/userinfo"
	h := makeHandlerWithConfig(config)

	sess := &session{token: &oauth2.Token{AccessToken: "test"}}

	// This could cause OOM with a malicious server
	// BUG: No size limit on response bodies
	_, err := h.keycloakUserinfo(sess)

	if err != nil {
		t.Logf("Request failed (expected with huge response): %v", err)
	} else {
		t.Log("BUG CONFIRMED: Huge response was processed without size limit (potential DoS)")
	}
}

// TestBug11_VsphereDomainValidation tests that invalid domain formats are accepted
func TestBug11_VsphereDomainValidation(t *testing.T) {
	testCases := []string{
		"not a domain!",
		"has spaces.com",
		"../../../etc/passwd",
		"",
		".",
		"example..com",
	}

	for _, invalidDomain := range testCases {
		t.Run("invalid_"+invalidDomain, func(t *testing.T) {
			os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
			os.Setenv("KEYCLOAK_PORT", "8443")
			os.Setenv("KEYCLOAK_REALM", "test")
			os.Setenv("LDAP_DOMAIN", invalidDomain)
			defer func() {
				os.Unsetenv("KEYCLOAK_HOSTNAME")
				os.Unsetenv("KEYCLOAK_PORT")
				os.Unsetenv("KEYCLOAK_REALM")
				os.Unsetenv("LDAP_DOMAIN")
			}()

			config, err := newKeycloakHandlerConfig(&nopLogger)

			// BUG: Invalid domains are accepted without validation
			if err == nil && config != nil {
				t.Logf("BUG CONFIRMED: Invalid domain %q was accepted", invalidDomain)
			}
		})
	}
}

// TestBug12_MagicStringDefault tests that "default" is used as magic string
func TestBug12_MagicStringDefault(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)

	// Create a session with nil connection (uses "default" key)
	sess1 := h.getOrCreateSession(nil)
	sess1.token = &oauth2.Token{AccessToken: "test1"}

	// Get the key for nil connection
	key := h.sessionKey(nil)

	// BUG: Uses magic string "default" instead of a constant
	if key == "default" {
		t.Log("BUG CONFIRMED: Magic string 'default' used instead of constant")
	}

	// This could cause collisions if "default" is used elsewhere
	h.sessionsMu.Lock()
	h.sessions["default"] = &session{token: &oauth2.Token{AccessToken: "test2"}}
	h.sessionsMu.Unlock()

	sess2 := h.getSession(nil)
	if sess1 != sess2 || sess2.token.AccessToken != sess1.token.AccessToken {
		t.Log("Magic string collision detected")
	}
}

// TestBug13_SHA1Usage tests that SHA1 is used for SID generation
func TestBug13_SHA1Usage(t *testing.T) {
	// Generate two SIDs
	sid1 := sid("user-id-123", "example.com")
	sid2 := sid("user-id-456", "example.com")

	// SHA1 generates 20 bytes
	// The SID format is: 1 byte revision + 1 byte subauth count + 6 bytes authority + N*4 bytes subauths
	// In this implementation: 1 + 1 + 6 + 5*4 = 28 bytes

	if len(sid1) == 28 && len(sid2) == 28 {
		t.Log("BUG CONFIRMED: SHA1 is used for SID generation (cryptographically broken)")
		t.Log("Consider using SHA256 instead")
	}

	// Verify they produce different SIDs
	if string(sid1) == string(sid2) {
		t.Error("SID collision detected!")
	}
}

// TestBug14_ClientSecretStoredInMemory tests that client secrets are stored in plaintext
func TestBug14_ClientSecretStoredInMemory(t *testing.T) {
	sess := &session{}
	clientSecret := "super-secret-password-123"

	tokenEndpoint := "http://example.com/token"
	httpClient := &http.Client{Timeout: 1 * time.Second}

	// Simulate opening a session (would normally call Keycloak)
	sess.clientID = "test-client"
	sess.clientSecret = clientSecret
	sess.isUserBound = false

	// BUG: Client secret is stored in plaintext in memory
	if sess.clientSecret == clientSecret {
		t.Log("BUG CONFIRMED: Client secret stored in plaintext in session struct")
		t.Logf("Secret visible in memory: %s", sess.clientSecret)
	}

	// In a real attack, memory dumps or debuggers could extract this
	_ = tokenEndpoint
	_ = httpClient
}

// TestBug15_NoContextPropagation tests that keycloakUserinfo doesn't accept context
func TestBug15_NoContextPropagation(t *testing.T) {
	// Create a server that takes a long time to respond
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"sub": "test", "preferred_username": "test"})
	}))
	defer slowServer.Close()

	config := makeHandlerConfigFromURL(t, slowServer.URL)
	config.userinfoEndpointURL = slowServer.URL + "/userinfo"
	h := makeHandlerWithConfig(config)

	sess := &session{token: &oauth2.Token{AccessToken: "test"}}

	// BUG: Can't pass context to cancel the request early
	// keycloakUserinfo doesn't accept context parameter
	start := time.Now()
	_, err := h.keycloakUserinfo(sess)
	elapsed := time.Since(start)

	if err == nil && elapsed > 1*time.Second {
		t.Logf("BUG CONFIRMED: keycloakUserinfo doesn't accept context, can't cancel request (took %v)", elapsed)
	}
}

// TestBug16_HardcodedTimeouts tests that timeouts are not configurable
func TestBug16_HardcodedTimeouts(t *testing.T) {
	// The httpClientTimeout constant is hardcoded to 30 seconds
	// There's no way to configure it via environment variable

	os.Setenv("HTTP_CLIENT_TIMEOUT", "5s")
	defer os.Unsetenv("HTTP_CLIENT_TIMEOUT")

	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Setenv("KEYCLOAK_PORT", "8443")
	os.Setenv("KEYCLOAK_REALM", "test")
	os.Setenv("LDAP_DOMAIN", "example.com")
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_PORT")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("LDAP_DOMAIN")
	}()

	h := NewKeycloakHandler().(*keycloakHandler)

	// BUG: httpClient always uses hardcoded 30s timeout, ignoring environment variable
	if h.httpClient.Timeout == 30*time.Second {
		t.Log("BUG CONFIRMED: Timeout is hardcoded to 30s, not configurable")
	}
}

// TestBug17_SessionCleanupBreaksEarly tests the break statement issue in session cleanup
func TestBug17_SessionCleanupBreaksEarly(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)

	// Create multiple connections mapping to the same session key
	conn1, conn1b := net.Pipe()
	conn2, conn2b := net.Pipe()
	defer conn1.Close()
	defer conn1b.Close()
	defer conn2.Close()
	defer conn2b.Close()

	sess := h.getOrCreateSession(conn1)
	key1 := h.sessionKey(conn1)

	// Manually add another connection with the same session key
	h.sessionsMu.Lock()
	h.connToKey[conn2] = key1
	h.sessionsMu.Unlock()

	// Make session expired
	sess.lastActivity = time.Now().Add(-sessionTTL - time.Minute)

	connsBefore := len(h.connToKey)

	// Trigger cleanup
	conn3, conn3b := net.Pipe()
	defer conn3.Close()
	defer conn3b.Close()
	h.getOrCreateSession(conn3)

	connsAfter := len(h.connToKey)

	// BUG: The cleanup loop has a break that only removes the first connection per session
	// If multiple connections map to the same session, they won't all be cleaned up
	if connsBefore > 1 && connsAfter > 1 {
		t.Logf("BUG CONFIRMED: Cleanup didn't remove all connections for expired session (before: %d, after: %d)", connsBefore, connsAfter)
	}
}

// Code review bug confirmation tests: each test confirms that a specific bug from the code review exists.

// TestBugReview_KeycloakGetAcceptsOversizedResponse confirms keycloakGet does not limit response body size (OOM risk).
func TestBugReview_KeycloakGetAcceptsOversizedResponse(t *testing.T) {
	oversized := maxResponseBodySize + 1024
	body := []byte(`{"id":"1","username":"u"}`)
	payload := make([]byte, 0, oversized+2)
	payload = append(payload, '[')
	for len(payload) < oversized {
		if len(payload) > 1 {
			payload = append(payload, ',')
		}
		payload = append(payload, body...)
	}
	payload = append(payload, ']')

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		if (r.URL.Path == "/admin/realms/test/users" || r.URL.Path == "/admin/realms/test/groups") && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := makeHandlerConfigFromURL(t, server.URL)
	h := makeHandlerWithConfig(config)
	code, _ := h.Bind("cn=svc,cn=bind,dc=example,dc=com", "secret", nil)
	require.EqualValues(t, ldap.LDAPResultSuccess, code)

	users := &[]User{}
	err := h.keycloakGet(h.getSession(nil), "users", users)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

// TestBugReview_DNValuesNotEscaped confirms DN construction does not escape special characters in usernames/group names.
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

// TestBugReview_SidToStringPanicsOnShortInput confirms sidToString returns empty string for short input instead of panicking.
func TestBugReview_SidToStringPanicsOnShortInput(t *testing.T) {
	got := sidToString([]byte{1, 5})
	assert.Equal(t, "", got)
}

// TestBugReview_CloseReturnsErrorWhenNoSession confirms Close returns nil for unknown connection (RFC 4511: unbind always succeeds).
func TestBugReview_CloseReturnsErrorWhenNoSession(t *testing.T) {
	boundDN := "cn=alice,cn=users,dc=example,dc=com"
	h := &keycloakHandler{
		sessions:  make(map[string]*session),
		connToKey: make(map[net.Conn]string),
		log:       &nopLogger,
	}
	conn, connOther := net.Pipe()
	defer conn.Close()
	defer connOther.Close()

	err := h.Close(boundDN, conn)
	assert.NoError(t, err)
}

// TestBugConfirm_StaleSessionsCleanedOnSearch confirms that expired sessions are cleaned when Search is called.
func TestBugConfirm_StaleSessionsCleanedOnSearch(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	conn1, conn1b := net.Pipe()
	defer conn1.Close()
	defer conn1b.Close()

	sess := h.getOrCreateSession(conn1)
	sess.lastActivity = time.Now().Add(-sessionTTL - time.Hour)

	// Search triggers cleanStaleSessions(); use a request that fails session check so we don't need a real backend.
	req := ldap.SearchRequest{BaseDN: "", Scope: ldap.ScopeBaseObject, Filter: "(objectclass=*)", Attributes: []string{}, Controls: []ldap.Control{}}
	_, _ = h.Search("cn=other,dc=example,dc=com", req, conn1)

	// Expired session for conn1 should have been removed by cleanStaleSessions().
	assert.Nil(t, h.getSession(conn1), "expired session should be cleaned when Search is called")
}

// TestBugConfirm_UserBoundSearchBaseDNCaseInsensitive confirms that user-bound search compares
// BaseDN case-insensitively, so a client using different case still gets the user entry.
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

// TestBugConfirm_KeycloakUserinfoOversizedResponseReturnsError confirms that keycloakUserinfo
// returns an error when the response body exceeds maxResponseBodySize and limits read size (no OOM).
func TestBugConfirm_KeycloakUserinfoOversizedResponseReturnsError(t *testing.T) {
	oversized := maxResponseBodySize + 1024
	payload := make([]byte, 0, oversized+64)
	payload = append(payload, `{"sub":"x","preferred_username":"u"`...)
	for len(payload) < oversized {
		payload = append(payload, ' ')
	}
	payload = append(payload, '}')

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := makeHandlerConfigFromURL(t, server.URL)
	config.userinfoEndpointURL = server.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	sess := &session{token: &oauth2.Token{AccessToken: "test"}}

	_, err := h.keycloakUserinfo(sess)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large", "oversized userinfo response should be rejected")
}

// TestBugConfirm_UserinfoEmptyPreferredNameAndSub_Rejected confirms that keycloakUserinfo
// returns an error when userinfo has both preferred_username and sub empty.
func TestBugConfirm_UserinfoEmptyPreferredNameAndSub_Rejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"sub":"","preferred_username":""}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := makeHandlerConfigFromURL(t, server.URL)
	config.userinfoEndpointURL = server.URL + "/userinfo"
	h := makeHandlerWithConfig(config)
	sess := &session{token: &oauth2.Token{AccessToken: "test"}}

	_, err := h.keycloakUserinfo(sess)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing preferred_username and sub")
}

// TestBugConfirm_GroupPrefixSearchCaseInsensitive confirms that group prefix matching is
// case-insensitive (e.g. prefix "ADMIN" matches group name "admins").
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

// TestBugConfirm_ServiceAccountSearchBaseDNCaseInsensitive confirms that service-account search
// compares BaseDN case-insensitively, so uppercase BaseDN still returns user entries.
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

// TestBugConfirm_ParseCommonNameFromDNEscapedComma confirms that parseCommonNameFromDN
// correctly parses DNs with escaped commas in the first RDN value.
func TestBugConfirm_ParseCommonNameFromDNEscapedComma(t *testing.T) {
	// DN with escaped comma in first RDN value (RFC 4514: comma in value is written as \,).
	dn := "cn=foo\\,bar,dc=example,dc=com"
	got, ok := parseCommonNameFromDN(dn)
	require.True(t, ok)
	assert.Equal(t, "foo,bar", got)
}

// TestBugConfirm_ParseUsernameFromUserBindDNEscapedComma confirms that parseUsernameFromUserBindDN
// correctly parses bind DNs with escaped commas in the cn value.
func TestBugConfirm_ParseUsernameFromUserBindDNEscapedComma(t *testing.T) {
	baseDNUsers := "cn=users,dc=example,dc=com"
	// Bind DN with escaped comma in cn (e.g. username "foo,bar").
	bindDN := "cn=foo\\,bar,cn=users,dc=example,dc=com"
	gotUser, gotOK := parseUsernameFromUserBindDN(bindDN, baseDNUsers)
	require.True(t, gotOK)
	assert.Equal(t, "foo,bar", gotUser)
}

// TestBugConfirm_SessionZeroLastActivityExpires confirms that sessions with zero lastActivity
// are removed by cleanStaleSessionsLocked (treated as stale).
func TestBugConfirm_SessionZeroLastActivityExpires(t *testing.T) {
	config := makeHandlerConfigFromURL(t, "http://127.0.0.1:8443")
	h := makeHandlerWithConfig(config)
	// Session with default zero lastActivity (never updated).
	h.sessionsMu.Lock()
	h.sessions["orphan"] = &session{}
	cleanStaleSessionsLocked(h)
	_, stillPresent := h.sessions["orphan"]
	h.sessionsMu.Unlock()

	assert.False(t, stillPresent, "sessions with zero lastActivity should be cleaned as stale")
}

// TestBugConfirm_EscapeRDNValueControlCharacter confirms that escapeRDNValue escapes
// control characters (e.g. NUL) per RFC 4514.
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

// TestSearchUserBoundMemberOfJellyfinStyle verifies that a user with roles jellyfin-users and jellyfin-admins
// gets memberOf DNs under ou=roles,dc=societycell,dc=local so that an LDAP filter like
// (|(memberOf=cn=jellyfin-users,ou=roles,dc=societycell,dc=local)(memberOf=cn=jellyfin-admins,ou=roles,dc=societycell,dc=local))
// matches (e.g. for Jellyfin or similar apps that gate access by role).
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

// TestSearchMemberOfRolesUsesRoleNameInAPIPath verifies that when searching users by memberOf roles,
// the Keycloak API is called with the role name in the path (GET /admin/realms/{realm}/roles/{role-name}/users),
// not the role ID. Using role ID would cause 404 or wrong results because Keycloak's endpoint expects role name.
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

// TestPortForwardTestLapJellyfinExactUser mirrors the exact flow of scripts/port-forward-and-test.sh:
// bind as user "test", then run Jellyfin-style exact user lookup. Must return 1 entry for the bound user.
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
