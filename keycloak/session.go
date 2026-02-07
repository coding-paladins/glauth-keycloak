package keycloak

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

func (h *keycloakHandler) sessionKey(conn net.Conn) string {
	if conn == nil {
		return defaultSessionKey
	}
	h.sessionsMu.RLock()
	defer h.sessionsMu.RUnlock()
	if h.connToKey != nil {
		if k, ok := h.connToKey[conn]; ok && k != "" {
			return k
		}
	}
	// For unknown connections, return a placeholder that won't match any real session
	// This prevents accidentally using "default" when connection-specific sessions exist
	return ""
}

func (h *keycloakHandler) getSession(conn net.Conn) *session {
	h.sessionsMu.RLock()
	defer h.sessionsMu.RUnlock()
	if h.sessions == nil {
		return nil
	}
	key := h.sessionKeyLocked(conn)
	if key == "" {
		return nil
	}
	return h.sessions[key]
}

// sessionKeyLocked returns the session key for a connection without acquiring the lock.
// Must be called with sessionsMu held.
func (h *keycloakHandler) sessionKeyLocked(conn net.Conn) string {
	if conn == nil {
		return defaultSessionKey
	}
	if h.connToKey != nil {
		if k, ok := h.connToKey[conn]; ok && k != "" {
			return k
		}
	}
	// Return empty string for unknown connections
	return ""
}

// cleanStaleSessions removes sessions that have exceeded sessionTTL. Safe to call from any handler.
func (h *keycloakHandler) cleanStaleSessions() {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	cleanStaleSessionsLocked(h)
}

// cleanStaleSessionsLocked removes sessions that have exceeded sessionTTL. Must be called with sessionsMu held.
func cleanStaleSessionsLocked(h *keycloakHandler) {
	if h.sessions == nil {
		return
	}
	now := time.Now()
	var staleKeys []string
	for k, s := range h.sessions {
		if s == nil ||
			s.lastActivity.IsZero() ||
			now.Sub(s.lastActivity) > sessionTTL {
			staleKeys = append(staleKeys, k)
		}
	}
	for _, k := range staleKeys {
		delete(h.sessions, k)
		if h.connToKey != nil {
			for c, id := range h.connToKey {
				if id == k {
					delete(h.connToKey, c)
				}
			}
		}
	}
}

// resolveOrCreateSessionKeyLocked returns the session key for conn, allocating one if needed. Must be called with sessionsMu held.
func resolveOrCreateSessionKeyLocked(h *keycloakHandler, conn net.Conn) string {
	key := defaultSessionKey
	if conn != nil {
		if h.connToKey == nil {
			h.connToKey = make(map[net.Conn]string)
		}
		if k, ok := h.connToKey[conn]; ok {
			key = k
		} else {
			key = fmt.Sprintf("conn-%d", atomic.AddUint64(&connectionKeyCounter, 1))
			h.connToKey[conn] = key
		}
	}
	return key
}

func (h *keycloakHandler) getOrCreateSession(conn net.Conn) *session {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	if h.sessions == nil {
		h.sessions = make(map[string]*session)
	}
	cleanStaleSessionsLocked(h)
	key := resolveOrCreateSessionKeyLocked(h, conn)
	if h.sessions[key] == nil {
		h.sessions[key] = &session{}
	}
	return h.sessions[key]
}

func (h *keycloakHandler) requireSession(conn net.Conn, boundDN string, refresh bool) (*session, error) {
	h.cleanStaleSessions()
	sess := h.getSession(conn)
	if err := h.checkSession(sess, boundDN, refresh, h.tokenEndpoint()); err != nil {
		return nil, err
	}
	return sess, nil
}

func (h *keycloakHandler) optionalSession(conn net.Conn, boundDN string) (*session, error) {
	h.cleanStaleSessions()
	sess := h.getSession(conn)
	if sess == nil {
		return nil, nil
	}
	if err := h.checkSession(sess, boundDN, false, h.tokenEndpoint()); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *session) open(
	log *zerolog.Logger,
	tokenEndpoint string,
	clientID string,
	clientSecret string,
	bindDN string,
	httpClient *http.Client,
) error {
	token, err := clientCredentialsGrant(log, tokenEndpoint, clientID, clientSecret, httpClient)
	if err != nil {
		return err
	}
	s.clientID = clientID
	s.clientSecret = clientSecret
	s.boundDN = &bindDN
	s.token = token
	s.isUserBound = false
	s.lastActivity = time.Now()
	return nil
}

func (s *session) refresh(log *zerolog.Logger, tokenEndpoint string, httpClient *http.Client) error {
	if s.token.Valid() {
		return nil
	}
	if s.isUserBound {
		return nil
	}
	if s.clientID == "" || s.clientSecret == "" {
		return errors.New("cannot refresh: missing client credentials")
	}
	token, err := clientCredentialsGrant(log, tokenEndpoint, s.clientID, s.clientSecret, httpClient)
	if err != nil {
		return err
	}
	s.token = token
	return nil
}

func (s *session) openUser(bindDN string, token *oauth2.Token) {
	s.boundDN = &bindDN
	s.token = token
	s.isUserBound = true
	s.clientID = ""
	s.clientSecret = ""
	s.lastActivity = time.Now()
}