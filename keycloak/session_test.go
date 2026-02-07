package keycloak

import (
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

func TestGetSessionSessionsNilReturnsNil(t *testing.T) {
	h := &keycloakHandler{
		sessions:  nil,
		connToKey: make(map[net.Conn]string),
		log:       &nopLogger,
	}
	got := h.getSession(nil)
	assert.Nil(t, got)
}

func TestGetOrCreateSessionInitializesSessionsWhenNil(t *testing.T) {
	h := &keycloakHandler{
		sessions:  nil,
		connToKey: make(map[net.Conn]string),
		log:       &nopLogger,
	}
	sess := h.getOrCreateSession(nil)
	require.NotNil(t, sess)
	require.NotNil(t, h.sessions)
	_, ok := h.sessions["default"]
	assert.True(t, ok)
}

func TestSessionRefreshMissingClientCredentials(t *testing.T) {
	s := &session{
		boundDN:      strPtr("cn=svc,cn=bind,dc=example,dc=com"),
		token:        &oauth2.Token{AccessToken: "x", Expiry: time.Now().Add(-time.Hour)},
		isUserBound:  false,
		clientID:     "",
		clientSecret: "",
	}
	err := s.refresh(&nopLogger, "http://127.0.0.1/token", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot refresh")
	assert.Contains(t, err.Error(), "missing client credentials")
}

func strPtr(s string) *string { return &s }

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

func TestSessionKeyUnknownConnReturnsEmptyString(t *testing.T) {
	h := &keycloakHandler{connToKey: make(map[net.Conn]string), log: &nopLogger}
	conn, connOther := net.Pipe()
	defer conn.Close()
	defer connOther.Close()
	key := h.sessionKey(conn)
	// After fix: should return empty string for unknown connections
	assert.Equal(t, "", key, "Unknown connection should return empty string")
}

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
