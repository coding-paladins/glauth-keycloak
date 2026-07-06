package keycloak

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

var nopLogger = zerolog.Nop()

var attributes3 = []string{
	"sAMAccountName",
	"description",
	"objectSid",
}

var attributes9 = []string{
	"uid",
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

// setRequiredKeycloakEnv sets KEYCLOAK_LDAP_CLIENT_ID/SECRET for NewKeycloakHandler tests.
func setRequiredKeycloakEnv(t *testing.T) {
	t.Helper()
	os.Setenv("KEYCLOAK_LDAP_CLIENT_ID", "ldap-client")
	os.Setenv("KEYCLOAK_LDAP_CLIENT_SECRET", "secret")
	t.Cleanup(func() {
		os.Unsetenv("KEYCLOAK_LDAP_CLIENT_ID")
		os.Unsetenv("KEYCLOAK_LDAP_CLIENT_SECRET")
	})
}

// withTestAuth wraps a mock Keycloak handler with a token response; optional next handles other paths.
// When next returns 404 with no body, falls back to Admin API role mocks and userinfo for user-bound search.
func withTestAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
			writeTestTokenResponse(w)
			return
		}
		if next != nil {
			rec := httptest.NewRecorder()
			next(rec, r)
			if rec.Code != http.StatusNotFound || rec.Body.Len() > 0 {
				for k, vals := range rec.Header() {
					for _, v := range vals {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(rec.Code)
				_, _ = w.Write(rec.Body.Bytes())
				return
			}
		}
		if r.URL.Path == "/admin/realms/test/clients" && r.Method == "GET" && r.URL.Query().Get("clientId") == "ldap-client" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]keycloakClient{{ID: "client-uuid", ClientID: "ldap-client"}})
			return
		}
		if handleTestUserClientRoles(w, r, "ldap-client", "client-uuid", r.URL.Query().Get("username"), []string{"user"}) {
			return
		}
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			writeTestUserinfoResponse(w, "ldap-client", "alice", nil)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeTestTokenResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": "tok",
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func writeTestUserinfoResponse(w http.ResponseWriter, clientID, username string, groups []string) {
	w.Header().Set("Content-Type", "application/json")
	payload := map[string]interface{}{
		"sub":                "sub-id",
		"preferred_username": username,
	}
	if groups != nil {
		payload["groups"] = groups
	}
	_ = json.NewEncoder(w).Encode(payload)
}

// handleTestUserClientRoles mocks Admin API user + client role lookup for user bind tests.
func handleTestUserClientRoles(w http.ResponseWriter, r *http.Request, clientID, clientUUID, username string, roleNames []string) bool {
	if r.URL.Path == "/admin/realms/test/users" && r.Method == "GET" && r.URL.Query().Get("username") == username {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]User{{ID: "user-id-1", Username: username}})
		return true
	}
	if r.URL.Path == "/admin/realms/test/clients" && r.Method == "GET" && r.URL.Query().Get("clientId") == clientID {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]keycloakClient{{ID: clientUUID, ClientID: clientID}})
		return true
	}
	rolesPath := "/admin/realms/test/users/user-id-1/role-mappings/clients/" + clientUUID
	compositePath := rolesPath + "/composite"
	if (r.URL.Path == rolesPath || r.URL.Path == compositePath) && r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		roles := make([]keycloakRole, 0, len(roleNames))
		for i, name := range roleNames {
			roles = append(roles, keycloakRole{ID: fmt.Sprintf("role-%d", i), Name: name})
		}
		_ = json.NewEncoder(w).Encode(roles)
		return true
	}
	return false
}

// withTestAuthForUser wraps withTestAuth with Admin API role mocks for user bind.
func withTestAuthForUser(clientID, clientUUID, username string, roleNames []string, next http.HandlerFunc) http.HandlerFunc {
	return withTestAuth(func(w http.ResponseWriter, r *http.Request) {
		if handleTestUserClientRoles(w, r, clientID, clientUUID, username, roleNames) {
			return
		}
		if next != nil {
			next(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
}

// handleTestTokenOrUserinfo serves password-grant token and userinfo for user bind tests.
func handleTestTokenOrUserinfo(w http.ResponseWriter, r *http.Request, clientID, username string) bool {
	if r.URL.Path == "/realms/test/protocol/openid-connect/token" && r.Method == "POST" {
		writeTestTokenResponse(w)
		return true
	}
	if r.URL.Path == "/userinfo" && r.Method == "GET" {
		if username == "" {
			username = "alice"
		}
		writeTestUserinfoResponse(w, clientID, username, nil)
		return true
	}
	return false
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
		baseDNRoles:     "cn=groups," + b,
		baseDNBindUsers: "cn=bind," + b,
		httpClient:      httpClient,
		sessions:        map[string]*session{"default": {}},
		log:             &nopLogger,
	}
}
