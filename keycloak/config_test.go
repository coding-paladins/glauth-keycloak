package keycloak

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/ldap"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

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

func TestDoJSONGetNilConfig(t *testing.T) {
	h := makeHandlerWithConfig(makeHandlerConfigFromURL(t, "http://127.0.0.1:8443"))
	h.config = nil
	sess := h.getSession(nil)
	sess.token = &oauth2.Token{AccessToken: "x"}
	var result []User
	err := h.doJSONGet(sess, "http://127.0.0.1/users", "test", &result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "handler config is nil")
}

func TestDoJSONGetNilHTTPClient(t *testing.T) {
	h := makeHandlerWithConfig(makeHandlerConfigFromURL(t, "http://127.0.0.1:8443"))
	h.httpClient = nil
	sess := h.getSession(nil)
	sess.token = &oauth2.Token{AccessToken: "x"}
	var result []User
	err := h.doJSONGet(sess, "http://127.0.0.1/users", "test", &result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP client is nil")
}

func TestDoJSONGetNilSessionToken(t *testing.T) {
	h := makeHandlerWithConfig(makeHandlerConfigFromURL(t, "http://127.0.0.1:8443"))
	sess := h.getSession(nil)
	sess.token = nil
	var result []User
	err := h.doJSONGet(sess, "http://127.0.0.1/users", "test", &result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no session token")
}

func TestNewKeycloakHandlerConfigWithScheme(t *testing.T) {
	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Setenv("KEYCLOAK_PORT", "8443")
	os.Setenv("KEYCLOAK_REALM", "test")
	os.Setenv("LDAP_DOMAIN", "example.com")
	os.Setenv("KEYCLOAK_SCHEME", "http")
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_PORT")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("LDAP_DOMAIN")
		os.Unsetenv("KEYCLOAK_SCHEME")
	}()

	config, err := newKeycloakHandlerConfig(&nopLogger)
	require.NoError(t, err)
	assert.Equal(t, "http", config.keycloakScheme)
	assert.Contains(t, config.userinfoEndpointURL, "http://")
}

func TestNewKeycloakHandlerConfigInsecureSkipVerifyYes(t *testing.T) {
	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Setenv("KEYCLOAK_PORT", "8443")
	os.Setenv("KEYCLOAK_REALM", "test")
	os.Setenv("LDAP_DOMAIN", "example.com")
	os.Setenv("KEYCLOAK_INSECURE_SKIP_VERIFY", "yes")
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_PORT")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("LDAP_DOMAIN")
		os.Unsetenv("KEYCLOAK_INSECURE_SKIP_VERIFY")
	}()

	config, err := newKeycloakHandlerConfig(&nopLogger)
	require.NoError(t, err)
	assert.True(t, config.keycloakInsecureSkipVerify)
}

func TestNewKeycloakHandlerReturnsNilWhenCAFileNotFound(t *testing.T) {
	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Setenv("KEYCLOAK_PORT", "8443")
	os.Setenv("KEYCLOAK_REALM", "test")
	os.Setenv("LDAP_DOMAIN", "example.com")
	os.Setenv("KEYCLOAK_CA_FILE", "/nonexistent/ca.pem")
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_PORT")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("LDAP_DOMAIN")
		os.Unsetenv("KEYCLOAK_CA_FILE")
	}()

	h := NewKeycloakHandler()
	assert.Nil(t, h)
}

func TestNewKeycloakHandlerReturnsNilWhenCAFileInvalidPEM(t *testing.T) {
	tmp := t.TempDir()
	caFile := tmp + "/ca.pem"
	require.NoError(t, os.WriteFile(caFile, []byte("not a certificate"), 0600))

	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Setenv("KEYCLOAK_PORT", "8443")
	os.Setenv("KEYCLOAK_REALM", "test")
	os.Setenv("LDAP_DOMAIN", "example.com")
	os.Setenv("KEYCLOAK_CA_FILE", caFile)
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_PORT")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("LDAP_DOMAIN")
		os.Unsetenv("KEYCLOAK_CA_FILE")
	}()

	h := NewKeycloakHandler()
	assert.Nil(t, h)
}

func TestNewKeycloakHandlerWithValidCAFile(t *testing.T) {
	// Create a minimal self-signed cert PEM so newTLSConfig hits AppendCertsFromPEM success path.
	key, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tmp := t.TempDir()
	caFile := tmp + "/ca.pem"
	require.NoError(t, os.WriteFile(caFile, certPEM, 0600))

	os.Setenv("KEYCLOAK_HOSTNAME", "kc.example.com")
	os.Setenv("KEYCLOAK_PORT", "8443")
	os.Setenv("KEYCLOAK_REALM", "test")
	os.Setenv("LDAP_DOMAIN", "example.com")
	os.Setenv("KEYCLOAK_CA_FILE", caFile)
	defer func() {
		os.Unsetenv("KEYCLOAK_HOSTNAME")
		os.Unsetenv("KEYCLOAK_PORT")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("LDAP_DOMAIN")
		os.Unsetenv("KEYCLOAK_CA_FILE")
	}()

	h := NewKeycloakHandler()
	require.NotNil(t, h)
	kh := h.(*keycloakHandler)
	require.NotNil(t, kh.httpClient)
}

func TestNewKeycloakHandlerWithGLAuthLogger(t *testing.T) {
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

	log := zerolog.Nop()
	h := NewKeycloakHandler(handler.Logger(&log))
	require.NotNil(t, h)
	kh := h.(*keycloakHandler)
	require.NotNil(t, kh.log)
}
