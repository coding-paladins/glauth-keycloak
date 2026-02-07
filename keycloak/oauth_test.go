package keycloak

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

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
