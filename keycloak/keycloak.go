// Package keycloak provides a GLAuth LDAP handler that authenticates and authorizes
// against Keycloak via OAuth 2.0 (client credentials and resource owner password grants).
package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/ldap"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

var connectionKeyCounter uint64

const sessionTTL = 30 * time.Minute

const defaultSessionKey = "default"

const maxResponseBodySize = 10 * 1024 * 1024 // 10MB limit for response bodies

var allowNilConnectionForTests bool

// userAccountControl value for normal, enabled user (Windows AD UF_NORMAL_ACCOUNT).
const userAccountControlNormal = "512"

type keycloakHandler struct {
	config          *keycloakHandlerConfig
	baseDNUsers     string
	baseDNGroups    string
	baseDNBindUsers string
	httpClient      *http.Client
	sessions        map[string]*session
	connToKey       map[net.Conn]string // maps connection to unique session key (avoids NAT collision)
	sessionsMu      sync.RWMutex
	log             *zerolog.Logger
}

type keycloakHandlerConfig struct {
	keycloakHostname           string
	keycloakPort               int
	keycloakRealm              string
	keycloakScheme             string // "https" in production; tests may use "http"
	ldapDomain                 string
	ldapClientID               string
	ldapClientSecret           string
	userinfoEndpointURL        string
	keycloakCAFile             string // optional PEM file for custom CA
	keycloakInsecureSkipVerify bool   // dev/test only: skip TLS verify
}

type session struct {
	clientID     string
	clientSecret string
	boundDN      *string
	token        *oauth2.Token
	isUserBound  bool
	lastActivity time.Time
}

// Handler (Binder)

func (h *keycloakHandler) Bind(
	bindDN string,
	bindSimplePw string,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	if conn == nil && !allowNilConnectionForTests {
		return ldap.LDAPResultOperationsError, errors.New("nil connection not allowed")
	}
	if h.config == nil {
		return ldap.LDAPResultOperationsError,
			errors.New("misconfiguration: handler config is nil")
	}
	h.logBindRequest(bindDN)

	s := h.getOrCreateSession(conn)

	// Service account bind: cn=<clientId>,cn=bind,<baseDN>
	sufBind := "," + h.baseDNBindUsers
	if clientID, ok := parseFirstCNValueFromBindDNWithSuffix(bindDN, sufBind); ok {
		clientSecret := bindSimplePw
		if err := s.open(h.log, h.tokenEndpoint(), clientID,
			clientSecret, bindDN, h.httpClient); err != nil {
			h.log.Error().Err(err).Msg("bind response")
			return ldap.LDAPResultInvalidCredentials, nil
		}
		h.logBindResponseServiceAccount(s.token.Expiry)
		return ldap.LDAPResultSuccess, nil
	}

	// User bind: cn=<username>,cn=users,<baseDN> — validate with Keycloak password grant
	sufUsers := "," + h.baseDNUsers
	if h.config.ldapClientID != "" && h.config.ldapClientSecret != "" &&
		strings.HasPrefix(bindDN, "cn=") && strings.HasSuffix(bindDN, sufUsers) {
		username, ok := parseUsernameFromUserBindDN(bindDN, h.baseDNUsers)
		if !ok {
			h.log.Error().Str("bindDN", bindDN).Msg("invalid user bindDN")
			return ldap.LDAPResultInvalidCredentials, nil
		}
		token, err := passwordGrant(h.log, h.tokenEndpoint(),
			h.config.ldapClientID, h.config.ldapClientSecret,
			username, bindSimplePw, h.httpClient)
		if err != nil {
			h.log.Error().Err(err).Str("username", username).Msg("user bind failed")
			return ldap.LDAPResultInvalidCredentials, nil
		}
		s.openUser(bindDN, token)
		h.logBindResponseUser(username)
		return ldap.LDAPResultSuccess, nil
	}

	h.log.Error().Str("baseBind", h.baseDNBindUsers).Str("baseUsers", h.baseDNUsers).Msg("invalid bindDN")
	return ldap.LDAPResultInvalidCredentials, nil
}

func (h *keycloakHandler) logBindRequest(bindDN string) {
	h.log.Info().
		Str("bindDN", bindDN).
		Msg("bind request")
}

func (h *keycloakHandler) logBindResponseServiceAccount(expiry time.Time) {
	h.log.Info().
		Time("expiry", expiry).
		Msg("bind response (service account)")
}

func (h *keycloakHandler) logBindResponseUser(username string) {
	h.log.Info().
		Str("username", username).
		Msg("bind response (user)")
}

// Handler (Closer)

func (h *keycloakHandler) Close(
	boundDN string,
	conn net.Conn,
) error {
	if conn == nil && !allowNilConnectionForTests {
		return errors.New("nil connection not allowed")
	}
	h.log.Info().
		Str("boundDN", boundDN).
		Msg("close request")
	sess, err := h.optionalSession(conn, boundDN)
	if err != nil {
		h.log.Error().Err(err).Msg("close response")
		return err
	}
	if sess == nil {
		h.log.Info().Msg("close response")
		// No session for this connection; idempotent success per RFC 4511
		return nil
	}
	h.sessionsMu.Lock()
	key := h.sessionKeyLocked(conn)
	if key == "" {
		h.sessionsMu.Unlock()
		h.log.Info().Msg("close response")
		return nil
	}
	if conn != nil && h.connToKey != nil {
		delete(h.connToKey, conn)
	}
	if h.sessions != nil {
		delete(h.sessions, key)
	}
	h.sessionsMu.Unlock()
	h.log.Info().Msg("close response")
	return nil
}

// Handler (Adder)

func (h *keycloakHandler) Add(
	boundDN string,
	req ldap.AddRequest,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	h.log.Debug().
		Str("boundDN", boundDN).
		Msg("add")
	return ldap.LDAPResultOperationsError, unexpected("Add")
}

// Handler (Modifier)

func (h *keycloakHandler) Modify(
	boundDN string,
	req ldap.ModifyRequest,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	h.log.Debug().
		Str("boundDN", boundDN).
		Msg("modify")
	return ldap.LDAPResultOperationsError, unexpected("Modify")
}

// Handler (Deleter)

func (h *keycloakHandler) Delete(
	boundDN string,
	deleteDN string,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	h.log.Debug().
		Str("boundDN", boundDN).
		Str("deleteDN", deleteDN).
		Msg("delete")
	return ldap.LDAPResultOperationsError, unexpected("Delete")
}

// Handler (HelperMaker)

func (h *keycloakHandler) FindUser(
	ctx context.Context,
	userName string,
	searchByUPN bool,
) (bool, config.User, error) {
	h.log.Debug().
		Str("userName", userName).
		Bool("searchByUPN", searchByUPN).
		Msg("findUser")
	user := config.User{}
	return false, user, unexpected("FindUser")
}

func (h *keycloakHandler) FindGroup(
	ctx context.Context,
	groupName string,
) (bool, config.Group, error) {
	h.log.Debug().
		Str("groupName", groupName).
		Msg("findGroup")
	group := config.Group{}
	return false, group, unexpected("FindGroup")
}

func (h *keycloakHandler) checkSession(s *session, boundDN string, refresh bool, tokenEndpoint string) error {
	if s == nil {
		return errors.New("no session")
	}
	if s.boundDN == nil || !strings.EqualFold(*s.boundDN, boundDN) {
		return fmt.Errorf("unexpected boundDN: %s", boundDN)
	}
	if s.token == nil {
		return errors.New("no session token")
	}
	s.lastActivity = time.Now()
	if !refresh {
		return nil
	}
	if s.isUserBound {
		if !s.token.Valid() {
			return errors.New("user token expired")
		}
		return nil
	}
	if err := s.refresh(h.log, tokenEndpoint, h.httpClient); err != nil {
		return err
	}
	return nil
}

func (h *keycloakHandler) tokenEndpoint() string {
	if h.config == nil {
		return ""
	}
	return h.config.tokenEndpoint()
}

// NewKeycloakHandler builds a GLAuth handler that uses Keycloak for authentication
// and group/user data. Configuration is read from environment variables.
// When GLAuth loads the plugin it passes handler.Logger(&s.log); we use that when
// present so debug = true in config affects plugin log level. Otherwise we use a
// fallback logger (same format as GLAuth pkg/logging).
// Returns nil if configuration or initialization fails.
func NewKeycloakHandler(opts ...handler.Option) handler.Handler {
	options := handler.NewOptions(opts...)
	var log *zerolog.Logger
	if options.Logger != nil {
		log = options.Logger
		log.Info().Msg("keycloak plugin: using GLAuth logger")
	} else {
		fallback := zerolog.New(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC1123Z,
		}).
			Level(zerolog.InfoLevel).
			With().
			Timestamp().
			Logger()
		log = &fallback
		log.Info().Msg("keycloak plugin: using fallback logger")
	}
	config, err := newKeycloakHandlerConfig(log)
	if err != nil {
		log.Error().Err(err).Msg("failed to initialize keycloak handler config")
		return nil
	}
	transport, err := newHTTPTransport(config)
	if err != nil {
		log.Error().Err(err).Msg("failed to create HTTP transport")
		return nil
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   httpClientTimeout,
	}
	domainParts := strings.Split(config.ldapDomain, ".")
	baseDN := "dc=" + strings.Join(domainParts, ",dc=")
	log.Info().
		Str("baseDN", baseDN).
		Msg("keycloak plugin loaded")
	return &keycloakHandler{
		config:          config,
		baseDNUsers:     "cn=users," + baseDN,
		baseDNGroups:    "cn=groups," + baseDN,
		baseDNBindUsers: "cn=bind," + baseDN,
		httpClient:      httpClient,
		sessions:        make(map[string]*session),
		connToKey:       make(map[net.Conn]string),
		log:             log,
	}
}
