// Package main provides a GLAuth LDAP handler that authenticates and authorizes
// against Keycloak via OAuth 2.0 (client credentials and resource owner password grants).
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/ldap"
	resty "github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
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
	restClient      *resty.Client
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

func (h *keycloakHandler) getOrCreateSession(conn net.Conn) *session {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	if h.sessions == nil {
		h.sessions = make(map[string]*session)
	}
	// lazy cleanup of stale sessions (e.g. client disconnected without Close)
	now := time.Now()
	var staleKeys []string
	for k, s := range h.sessions {
		if !s.lastActivity.IsZero() && now.Sub(s.lastActivity) > sessionTTL {
			staleKeys = append(staleKeys, k)
		}
	}
	// Clean up stale sessions and their connections
	for _, k := range staleKeys {
		delete(h.sessions, k)
		if h.connToKey != nil {
			// Remove all connections that map to this session key
			for c, id := range h.connToKey {
				if id == k {
					delete(h.connToKey, c)
				}
			}
		}
	}
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
	if h.sessions[key] == nil {
		h.sessions[key] = &session{}
	}
	return h.sessions[key]
}

type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type User struct {
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	ID        string `json:"id"`
	LastName  string `json:"lastName"`
	Username  string `json:"username"`
}

type userinfoResponse struct {
	Sub           string   `json:"sub"`
	PreferredName string   `json:"preferred_username"`
	Email         string   `json:"email"`
	Name          string   `json:"name"`
	GivenName     string   `json:"given_name"`
	FamilyName    string   `json:"family_name"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `json:"groups"` // optional: Keycloak groups mapper with "Add to userinfo"
	Roles         []string `json:"-"`      // all roles: filled from "roles", "realm_roles", or "realm_access.roles"
}

// userinfoRolesRaw is used to unmarshal role claims from userinfo (Keycloak can send any of these shapes).
type userinfoRolesRaw struct {
	Roles       []string `json:"roles"`
	RealmRoles  []string `json:"realm_roles"`
	RealmAccess *struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// userinfoDecode has all userinfo fields at top level so flat Keycloak JSON unmarshals correctly.
type userinfoDecode struct {
	Sub            string                    `json:"sub"`
	PreferredName  string                    `json:"preferred_username"`
	Email          string                    `json:"email"`
	Name           string                    `json:"name"`
	GivenName      string                    `json:"given_name"`
	FamilyName     string                    `json:"family_name"`
	EmailVerified  bool                      `json:"email_verified"`
	Groups         []string                  `json:"groups"`
	Roles          []string                  `json:"roles"`
	RealmRoles     []string                  `json:"realm_roles"`
	RealmAccess    *struct{ Roles []string } `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

// UnmarshalJSON fills userinfoResponse including Roles: realm roles plus client roles with "clientId:roleName" prefix.
func (u *userinfoResponse) UnmarshalJSON(data []byte) error {
	var dec userinfoDecode
	if err := json.Unmarshal(data, &dec); err != nil {
		return err
	}
	u.Sub = dec.Sub
	u.PreferredName = dec.PreferredName
	u.Email = dec.Email
	u.Name = dec.Name
	u.GivenName = dec.GivenName
	u.FamilyName = dec.FamilyName
	u.EmailVerified = dec.EmailVerified
	u.Groups = dec.Groups
	u.Roles = rolesFromDecode(&dec)
	return nil
}

// rolesFromDecode builds a single list: realm roles as-is, then each client role as "clientId:roleName".
func rolesFromDecode(dec *userinfoDecode) []string {
	var out []string
	// Realm roles: prefer top-level "roles", then "realm_roles", then "realm_access.roles"
	var realm []string
	if len(dec.Roles) > 0 {
		realm = dec.Roles
	} else if len(dec.RealmRoles) > 0 {
		realm = dec.RealmRoles
	} else if dec.RealmAccess != nil && len(dec.RealmAccess.Roles) > 0 {
		realm = dec.RealmAccess.Roles
	}
	for _, r := range realm {
		if r != "" {
			out = append(out, r)
		}
	}
	// Client roles with client name prefix
	if len(dec.ResourceAccess) > 0 {
		for clientID, access := range dec.ResourceAccess {
			clientID = strings.TrimSpace(clientID)
			if clientID == "" {
				continue
			}
			for _, r := range access.Roles {
				if r != "" {
					out = append(out, clientID+":"+r)
				}
			}
		}
	}
	return out
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
	h.log.Info().
		Str("bindDN", bindDN).
		Msg("bind request")
	if h.config == nil {
		return ldap.LDAPResultOperationsError,
			errors.New("misconfiguration: handler config is nil")
	}

	s := h.getOrCreateSession(conn)

	// Service account bind: cn=<clientId>,cn=bind,<baseDN>
	preBind := "cn="
	sufBind := "," + h.baseDNBindUsers
	if strings.HasPrefix(bindDN, preBind) && strings.HasSuffix(bindDN, sufBind) {
		clientID := strings.TrimPrefix(strings.TrimSuffix(bindDN, sufBind), preBind)
		clientSecret := bindSimplePw
		if err := s.open(h.log, h.tokenEndpoint(), clientID,
			clientSecret, bindDN, h.httpClient); err != nil {
			h.log.Error().Err(err).Msg("bind response")
			return ldap.LDAPResultInvalidCredentials, nil
		}
		h.log.Info().
			Time("expiry", s.token.Expiry).
			Msg("bind response (service account)")
		return ldap.LDAPResultSuccess, nil
	}

	// User bind: cn=<username>,cn=users,<baseDN> — validate with Keycloak password grant
	sufUsers := "," + h.baseDNUsers
	if h.config.ldapClientID != "" && h.config.ldapClientSecret != "" &&
		strings.HasPrefix(bindDN, preBind) && strings.HasSuffix(bindDN, sufUsers) {
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
		h.log.Info().Str("username", username).Msg("bind response (user)")
		return ldap.LDAPResultSuccess, nil
	}

	h.log.Error().Str("baseBind", h.baseDNBindUsers).Str("baseUsers", h.baseDNUsers).Msg("invalid bindDN")
	return ldap.LDAPResultInvalidCredentials, nil
}

var rootDSEAttributes = []string{
	"configurationNamingContext",
	"currentTime",
	"defaultNamingContext",
	"dnsHostName",
	"domainControllerFunctionality",
	"domainFunctionality",
	"dsServiceName",
	"forestFunctionality",
	"highestCommittedUSN",
	"isGlobalCatalogReady",
	"isSynchronized",
	"ldapServiceName",
	"namingContexts",
	"rootDomainNamingContext",
	"schemaNamingContext",
	"serverName",
	"subschemaSubentry",
	"supportedCapabilities",
	"supportedControl",
	"supportedLDAPPolicies",
	"supportedLDAPVersion",
	"supportedSASLMechanisms"}

var filterGroupsWithPrefix = regexp.MustCompile("^\\(&\\(objectClass=group\\)" +
	"\\(\\|\\(sAMAccountName=(.+)\\*\\)" +
	"\\(cn=(.*)\\*\\)\\)\\)$")
var filterRootDSE = regexp.MustCompile("^\\(objectclass=\\*\\)$")
var filterUsers = regexp.MustCompile("^\\(objectClass=user\\)$")
var filterUsersWithPrefix = regexp.MustCompile("^\\(&\\(objectClass=user\\)" +
	"\\(\\|\\(sAMAccountName=(.+)\\*\\)" +
	"\\(sn=(.+)\\*\\)" +
	"\\(givenName=(.*)\\*\\)" +
	"\\(cn=(.*)\\*\\)" +
	"\\(displayname=(.*)\\*\\)" +
	"\\(userPrincipalName=(.*)\\*\\)\\)\\)$")

var attributes0 = []string{}
var attributes3 = []string{
	"sAMAccountName",
	"description",
	"objectSid"}
var attributes9 = []string{
	"sAMAccountName",
	"userPrincipalName",
	"description",
	"givenName",
	"sn",
	"mail",
	"userAccountControl",
	"lockoutTime",
	"objectSid"}

var controls0 = []string{}
var controls1 = []string{ldap.ControlTypePaging}

// Handler (Searcher)

func (h *keycloakHandler) Search(
	boundDN string,
	req ldap.SearchRequest,
	conn net.Conn,
) (ldap.ServerSearchResult, error) {
	if conn == nil && !allowNilConnectionForTests {
		err := errors.New("nil connection not allowed")
		h.log.Error().Err(err).Msg("search response")
		return errorSearchResult(), err
	}
	scope := ldap.ScopeMap[req.Scope]
	deferAliases := ldap.DerefMap[req.DerefAliases]
	c := make([]string, len(req.Controls))
	for i, cc := range req.Controls {
		if s, ok := ldap.ControlTypeMap[cc.GetControlType()]; ok {
			c[i] = s
		} else {
			c[i] = cc.GetControlType()
		}
	}
	controls := strings.Join(c, " ")
	attributes := strings.Join(req.Attributes, " ")
	h.log.Info().
		Str("boundDN", boundDN).
		Str("baseDN", req.BaseDN).
		Str("scope", scope).
		Str("derefAliases", deferAliases).
		Int("sizeLimit", req.SizeLimit).
		Int("timeLimit", req.TimeLimit).
		Bool("typesOnly", req.TypesOnly).
		Str("filter", req.Filter).
		Str("attributes", attributes).
		Str("controls", controls).
		Msg("search request")

	sess := h.getSession(conn)
	if err := h.checkSession(sess, boundDN, true, h.tokenEndpoint()); err != nil {
		h.log.Error().Err(err).Msg("search response")
		return errorSearchResult(), err
	}
	if sess.isUserBound {
		return h.userBoundSearchResult(sess, boundDN, req)
	}
	if req.DerefAliases != ldap.NeverDerefAliases ||
		req.SizeLimit != 0 ||
		req.TimeLimit != 0 ||
		req.TypesOnly {

		err := unexpected(fmt.Sprintf("deferAliases: \"%s\", "+
			"sizeLimit: %d, "+
			"timeLimit: %d, "+
			"typesOnly: %t",
			deferAliases,
			req.SizeLimit,
			req.TimeLimit,
			req.TypesOnly))
		h.log.Error().Err(err).Msg("search response")
		return errorSearchResult(), err
	} else if _, ok := checkSearchRequest(
		req,
		"",
		ldap.ScopeBaseObject,
		filterRootDSE,
		attributes0,
		controls0); ok {

		res := h.rootDSESearchResult()
		h.log.Debug().
			Str("BaseDN", req.BaseDN).
			Int("entries", len(res.Entries)).
			Msg("search response")
		return res, nil
	} else if _, ok := checkSearchRequest(
		req,
		h.baseDNUsers,
		ldap.ScopeWholeSubtree,
		filterUsers,
		attributes9,
		controls1); ok {

		if res, err := h.usersSearchResult(sess, ""); err != nil {
			h.log.Error().Err(err).Msg("search response")
			return errorSearchResult(), err
		} else {
			h.log.Debug().
				Str("BaseDN", req.BaseDN).
				Int("entries", len(res.Entries)).
				Msg("search response")
			return res, nil
		}
	} else if prefix, ok := checkSearchRequest(
		req,
		h.baseDNUsers,
		ldap.ScopeWholeSubtree,
		filterUsersWithPrefix,
		attributes9,
		controls1); ok {

		if res, err := h.usersSearchResult(sess, prefix); err != nil {
			h.log.Error().Err(err).Msg("search response")
			return errorSearchResult(), err
		} else {
			h.log.Debug().
				Str("BaseDN", req.BaseDN).
				Str("prefix", prefix).
				Int("entries", len(res.Entries)).
				Msg("search response")
			return res, nil
		}
	} else if prefix, ok := checkSearchRequest(req,
		h.baseDNGroups,
		ldap.ScopeWholeSubtree,
		filterGroupsWithPrefix,
		attributes3,
		controls1); ok {

		if res, err := h.groupsSearchResult(sess, prefix); err != nil {
			return errorSearchResult(), err
		} else {
			h.log.Debug().
				Str("BaseDN", req.BaseDN).
				Str("prefix", prefix).
				Int("entries", len(res.Entries)).
				Msg("search response")
			return res, nil
		}
	} else {
		err := unexpected(fmt.Sprintf("baseDN: \"%s\", "+
			"scope: \"%s\", "+
			"filter: \"%s\", "+
			"attributes: \"%s\", "+
			"controls: \"%s\"",
			req.BaseDN,
			scope,
			req.Filter,
			attributes,
			controls))
		h.log.Error().Err(err).Msg("search response")
		return errorSearchResult(), err
	}
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
	sess := h.getSession(conn)
	if err := h.checkSession(sess, boundDN, false, h.tokenEndpoint()); err != nil {
		h.log.Error().Err(err).Msg("close response")
		return err
	}
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	key := h.sessionKeyLocked(conn)
	if key == "" {
		// No session for this connection
		return nil
	}
	if conn != nil && h.connToKey != nil {
		delete(h.connToKey, conn)
	}
	if h.sessions != nil {
		delete(h.sessions, key)
	}
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

func (h *keycloakHandler) groupsSearchResult(
	s *session,
	prefix string,
) (ldap.ServerSearchResult, error) {
	groups := &[]Group{}
	err := h.keycloakGet(s, "groups", groups)
	if err != nil {
		return errorSearchResult(), err
	}

	e := make([]*ldap.Entry, 0, len(*groups))
	for _, group := range *groups {
		if !strings.HasPrefix(group.Name, prefix) {
			continue
		}

		a := make([]*ldap.EntryAttribute, 5)
		o := sid(group.Name, h.config.ldapDomain)
		a[0] = newAttribute("objectClass", "group")
		a[1] = newAttribute("sAMAccountName", group.Name)
		a[2] = newAttribute("cn", group.Name)
		a[3] = newAttribute("description", group.Name)
		// objectSid: binary SID as string (glauth ldap uses Values []string only)
		a[4] = newAttribute("objectSid", string(o))
		h.log.Debug().
			Str("name", group.Name).
			Str("objectSid", sidToString(o)).
			Msg("group")

		dn := fmt.Sprintf("cn=%s,%s", group.Name, h.baseDNGroups)
		e = append(e, &ldap.Entry{DN: dn, Attributes: a})
	}

	return ldap.ServerSearchResult{
		Entries:    e,
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess}, nil
}

func (h *keycloakHandler) keycloakGet(
	s *session,
	path string,
	result interface{},
) error {
	if h.config == nil {
		return errors.New("keycloak REST API: handler config is nil")
	}
	if h.restClient == nil {
		return errors.New("keycloak REST API: rest client is nil")
	}
	if s == nil || s.token == nil {
		return errors.New("keycloak REST API: no session token")
	}
	u := h.config.restAPIEndpoint(path)
	h.log.Debug().
		Str("method", "GET").
		Str("url", u).
		Msg("keycloak REST API request")

	res, err := h.restClient.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(s.token.AccessToken).
		SetResult(result).
		Get(u)
	if err == nil && res.StatusCode() != http.StatusOK {
		h.log.Error().
			Int("status", res.StatusCode()).
			Str("statusText", res.Status()).
			Str("body", string(res.Body())).
			Msg("keycloak REST API non-200")
		err = fmt.Errorf("keycloak REST API: %s", res.Status())
	}
	if err != nil {
		h.log.Error().Err(err).Msg("keycloak REST API response")
		return err
	}
	h.log.Debug().Msg("keycloak REST API response")
	return nil
}

func (h *keycloakHandler) rootDSESearchResult() ldap.ServerSearchResult {
	a := make([]*ldap.EntryAttribute, len(rootDSEAttributes))
	for i, name := range rootDSEAttributes {
		a[i] = &ldap.EntryAttribute{
			Name:   name,
			Values: []string{""}}
	}
	e := &ldap.Entry{DN: "", Attributes: a}

	return ldap.ServerSearchResult{
		Entries:    []*ldap.Entry{e},
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess,
	}
}

func (h *keycloakHandler) usersSearchResult(
	s *session,
	prefix string,
) (ldap.ServerSearchResult, error) {
	users := &[]User{}
	err := h.keycloakGet(s, "users", users)
	if err != nil {
		return errorSearchResult(), err
	}

	e := make([]*ldap.Entry, 0, len(*users))
	prefixLower := strings.ToLower(prefix)
	for _, user := range *users {
		userPrincipalName := fmt.Sprintf("%s@%s", user.Username, h.config.ldapDomain)
		displayName := strings.TrimSpace(strings.TrimSpace(user.FirstName + " " + user.LastName))
		usernameLower := strings.ToLower(user.Username)
		lastNameLower := strings.ToLower(user.LastName)
		firstNameLower := strings.ToLower(user.FirstName)
		emailLower := strings.ToLower(user.Email)
		userPrincipalNameLower := strings.ToLower(userPrincipalName)
		displayNameLower := strings.ToLower(displayName)
		// Check if prefix matches any of the searchable fields:
		// sAMAccountName (Username), sn (LastName), givenName (FirstName),
		// cn (Username), displayname, userPrincipalName (Email/Username)
		if prefix != "" &&
			!strings.HasPrefix(usernameLower, prefixLower) &&
			!strings.HasPrefix(lastNameLower, prefixLower) &&
			!strings.HasPrefix(firstNameLower, prefixLower) &&
			!strings.HasPrefix(emailLower, prefixLower) &&
			!strings.HasPrefix(userPrincipalNameLower, prefixLower) &&
			(displayNameLower == "" || !strings.HasPrefix(displayNameLower, prefixLower)) {
			continue
		}

		objectSidBytes := sid(user.ID, h.config.ldapDomain)
		a := make([]*ldap.EntryAttribute, 11)
		a[0] = newAttribute("objectClass", "user")
		a[1] = newAttribute("sAMAccountName", user.Username)
		a[2] = newAttribute("userPrincipalName", userPrincipalName)
		a[3] = newAttribute("cn", user.Username)
		a[4] = newAttribute("givenName", user.FirstName)
		a[5] = newAttribute("sn", user.LastName)
		a[6] = newAttribute("mail", user.Email)
		a[7] = newAttribute("description", "")
		a[8] = newAttribute("userAccountControl", userAccountControlNormal)
		a[9] = newAttribute("lockoutTime", "0")
		// objectSid: binary SID as string (glauth ldap uses Values []string only)
		a[10] = newAttribute("objectSid", string(objectSidBytes))

		h.log.Debug().
			Str("username", user.Username).
			Msg("user")

		dn := fmt.Sprintf("cn=%s,%s", user.Username, h.baseDNUsers)
		e = append(e, &ldap.Entry{DN: dn, Attributes: a})
	}

	return ldap.ServerSearchResult{
		Entries:    e,
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess}, nil
}

func (h *keycloakHandler) userBoundSearchResult(
	s *session,
	boundDN string,
	req ldap.SearchRequest,
) (ldap.ServerSearchResult, error) {
	info, err := h.keycloakUserinfo(s)
	if err != nil {
		h.log.Error().Err(err).Msg("userinfo failed")
		return errorSearchResult(), err
	}
	userDN := fmt.Sprintf("cn=%s,%s", info.PreferredName, h.baseDNUsers)
	entryDN := userDN
	if boundDN != "" {
		entryDN = boundDN
	}
	userPrincipalName := fmt.Sprintf("%s@%s", info.PreferredName, h.config.ldapDomain)
	samAccountName := info.PreferredName
	commonName := info.PreferredName
	if boundCN, ok := parseCommonNameFromDN(boundDN); ok {
		samAccountName = boundCN
		commonName = boundCN
	}
	objectSidBytes := sid(info.Sub, h.config.ldapDomain)
	a := make([]*ldap.EntryAttribute, 11)
	a[0] = newAttribute("objectClass", "user")
	a[1] = newAttribute("sAMAccountName", samAccountName)
	a[2] = newAttribute("userPrincipalName", userPrincipalName)
	a[3] = newAttribute("cn", commonName)
	a[4] = newAttribute("givenName", info.GivenName)
	a[5] = newAttribute("sn", info.FamilyName)
	a[6] = newAttribute("mail", info.Email)
	a[7] = newAttribute("description", "")
	a[8] = newAttribute("userAccountControl", userAccountControlNormal)
	a[9] = newAttribute("lockoutTime", "0")
	// objectSid: binary SID as string (glauth ldap uses Values []string only)
	a[10] = newAttribute("objectSid", string(objectSidBytes))
	rolesBaseDN := "ou=roles," + strings.TrimPrefix(h.baseDNUsers, "cn=users,")
	memberOfValues := make([]string, 0)
	if len(info.Groups) > 0 {
		for _, g := range info.Groups {
			cn := groupPathToCN(g)
			if cn != "" {
				memberOfValues = append(memberOfValues, fmt.Sprintf("cn=%s,%s", cn, h.baseDNGroups))
			}
		}
	}
	realmRoleNames := realmRolesFromUserinfo(info)
	for _, r := range realmRoleNames {
		if r != "" {
			memberOfValues = append(memberOfValues, fmt.Sprintf("cn=%s,%s", r, rolesBaseDN))
		}
	}
	if len(memberOfValues) > 0 {
		a = append(a, &ldap.EntryAttribute{Name: "memberOf", Values: memberOfValues})
	}
	entry := &ldap.Entry{DN: entryDN, Attributes: a}

	if req.BaseDN != h.baseDNUsers && req.BaseDN != userDN && req.BaseDN != boundDN {
		return ldap.ServerSearchResult{
			Entries:    []*ldap.Entry{},
			Referrals:  nil,
			Controls:   nil,
			ResultCode: ldap.LDAPResultSuccess}, nil
	}
	if req.Scope != ldap.ScopeBaseObject && req.Scope != ldap.ScopeSingleLevel && req.Scope != ldap.ScopeWholeSubtree {
		return ldap.ServerSearchResult{
			Entries:    []*ldap.Entry{},
			Referrals:  nil,
			Controls:   nil,
			ResultCode: ldap.LDAPResultSuccess}, nil
	}
	if req.Scope == ldap.ScopeBaseObject && req.BaseDN != userDN && req.BaseDN != boundDN {
		return ldap.ServerSearchResult{
			Entries:    []*ldap.Entry{},
			Referrals:  nil,
			Controls:   nil,
			ResultCode: ldap.LDAPResultSuccess}, nil
	}
	if filterUsers.MatchString(req.Filter) || filterUsersWithPrefix.MatchString(req.Filter) {
		return ldap.ServerSearchResult{
			Entries:    []*ldap.Entry{entry},
			Referrals:  nil,
			Controls:   nil,
			ResultCode: ldap.LDAPResultSuccess}, nil
	}
	return ldap.ServerSearchResult{
		Entries:    []*ldap.Entry{},
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess}, nil
}

func (h *keycloakHandler) keycloakUserinfo(s *session) (*userinfoResponse, error) {
	if h.config == nil {
		return nil, errors.New("userinfo: handler config is nil")
	}
	if h.restClient == nil {
		return nil, errors.New("userinfo: rest client is nil")
	}
	if s == nil || s.token == nil {
		return nil, errors.New("userinfo: no session token")
	}
	res, err := h.restClient.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(s.token.AccessToken).
		Get(h.config.userinfoEndpointURL)
	if err != nil {
		return nil, err
	}
	if res.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("userinfo: %s", res.Status())
	}
	// Limit response body size to prevent DoS
	body := res.Body()
	if len(body) > maxResponseBodySize {
		return nil, fmt.Errorf("userinfo: response body too large (%d bytes, max %d)", len(body), maxResponseBodySize)
	}
	var info userinfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}
	if info.PreferredName == "" {
		info.PreferredName = info.Sub
	}
	return &info, nil
}

func (c *keycloakHandlerConfig) restAPIEndpoint(path string) string {
	scheme := c.keycloakScheme
	if scheme == "" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d/admin/realms/%s/%s",
		scheme,
		c.keycloakHostname,
		c.keycloakPort,
		c.keycloakRealm,
		path)
}

func (c *keycloakHandlerConfig) tokenEndpoint() string {
	scheme := c.keycloakScheme
	if scheme == "" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d/realms/%s/protocol/openid-connect/token",
		scheme,
		c.keycloakHostname,
		c.keycloakPort,
		c.keycloakRealm)
}

func (h *keycloakHandler) tokenEndpoint() string {
	if h.config == nil {
		return ""
	}
	return h.config.tokenEndpoint()
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
	restClient := resty.New().
		SetTransport(transport).
		SetTimeout(httpClientTimeout)
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
		restClient:      restClient,
		httpClient:      httpClient,
		sessions:        make(map[string]*session),
		connToKey:       make(map[net.Conn]string),
		log:             log,
	}
}

func checkSearchRequest(
	req ldap.SearchRequest,
	baseDN string,
	scope int,
	filterRegexp *regexp.Regexp,
	attributes []string,
	controls []string,
) (string, bool) {
	if req.BaseDN != baseDN ||
		req.Scope != scope ||
		len(req.Attributes) != len(attributes) ||
		len(req.Controls) != len(controls) {
		return "", false
	}
	if !sameStringMultiset(req.Attributes, attributes) {
		return "", false
	}
	controlTypes := make([]string, 0, len(req.Controls))
	for _, control := range req.Controls {
		controlTypes = append(controlTypes, control.GetControlType())
	}
	if !sameStringMultiset(controlTypes, controls) {
		return "", false
	}

	if g := filterRegexp.FindStringSubmatch(req.Filter); g == nil {
		return "", false
	} else if len(g) == 1 {
		return "", true // no prefix
	} else {
		// use first non-empty capture as prefix (capture groups may differ, e.g. jo vs john)
		for _, cap := range g[1:] {
			if cap != "" {
				return cap, true
			}
		}
		return "", true
	}
}

func sameStringMultiset(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

func clientCredentialsGrant(
	log *zerolog.Logger,
	tokenEndpoint string,
	clientID string,
	clientSecret string,
	httpClient *http.Client,
) (*oauth2.Token, error) {
	oauth2Config := &clientcredentials.Config{
		TokenURL:       tokenEndpoint,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		Scopes:         nil,
		EndpointParams: url.Values{}}

	// Create context with timeout to prevent hanging requests
	ctx, cancel := context.WithTimeout(context.Background(), httpClientTimeout)
	defer cancel()

	if httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}
	log.Debug().
		Str("endpoint", tokenEndpoint).
		Str("grant_type", "client_credentials").
		Str("client_id", clientID).
		Msg("oauth 2.0 authorization request")

	token, err := oauth2Config.TokenSource(ctx).Token()
	if err != nil {
		log.Error().Err(err).Msg("oauth 2.0 error response")
		return nil, err
	}
	if !token.Valid() {
		err := errors.New("invalid token")
		log.Error().Err(err).Msg("oauth 2.0 error response")
		return nil, err
	}
	log.Debug().Msg("oauth 2.0 access token response")
	return token, nil
}

func passwordGrant(
	log *zerolog.Logger,
	tokenEndpoint string,
	clientID string,
	clientSecret string,
	username string,
	password string,
	httpClient *http.Client,
) (*oauth2.Token, error) {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("username", username)
	data.Set("password", password)
	data.Set("scope", "openid")

	log.Debug().
		Str("endpoint", tokenEndpoint).
		Str("grant_type", "password").
		Str("username", username).
		Msg("oauth 2.0 password grant request")

	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: httpClientTimeout}
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), httpClientTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		log.Error().Err(err).Msg("password grant request creation failed")
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("password grant request failed")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Error().
			Str("status", resp.Status).
			Int("code", resp.StatusCode).
			Str("body", string(body)).
			Msg("password grant error response")
		return nil, errors.New("invalid credentials")
	}

	var tr struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	// Limit response body size to prevent DoS
	limitedReader := io.LimitReader(resp.Body, maxResponseBodySize)
	if err := json.NewDecoder(limitedReader).Decode(&tr); err != nil {
		log.Error().Err(err).Msg("password grant decode failed")
		return nil, err
	}
	if tr.AccessToken == "" {
		return nil, errors.New("invalid token")
	}
	tok := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		TokenType:    tr.TokenType,
		RefreshToken: tr.RefreshToken,
	}
	if tr.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	log.Debug().Msg("oauth 2.0 password grant success")
	return tok, nil
}

// realmRolesFromUserinfo returns all role names from the userinfo response (Roles is filled from any Keycloak role claim).
func realmRolesFromUserinfo(info *userinfoResponse) []string {
	if info == nil || len(info.Roles) == 0 {
		return nil
	}
	return info.Roles
}

// groupPathToCN turns a Keycloak group path (e.g. "/admins" or "/parent/child") into an LDAP cn value (last segment).
func groupPathToCN(path string) string {
	path = strings.TrimPrefix(strings.TrimSpace(path), "/")
	if path == "" {
		return ""
	}
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	return path
}

func parseUsernameFromUserBindDN(bindDN string, baseDNUsers string) (username string, ok bool) {
	sufUsers := "," + baseDNUsers
	if !strings.HasPrefix(bindDN, "cn=") || !strings.HasSuffix(bindDN, sufUsers) {
		return "", false
	}
	rest := strings.TrimSuffix(bindDN, sufUsers)
	if rest == bindDN {
		return "", false
	}
	username = strings.TrimPrefix(rest, "cn=")
	if i := strings.Index(username, ","); i >= 0 {
		username = username[:i]
	}
	// Validate username is non-empty
	if username == "" {
		return "", false
	}
	return username, true
}

func parseCommonNameFromDN(dn string) (string, bool) {
	if dn == "" {
		return "", false
	}
	parts := strings.Split(dn, ",")
	if len(parts) == 0 {
		return "", false
	}
	first := strings.TrimSpace(parts[0])
	if !strings.HasPrefix(strings.ToLower(first), "cn=") {
		return "", false
	}
	cn := strings.TrimSpace(first[3:])
	if cn == "" {
		return "", false
	}
	return cn, true
}

func envNotSet(key string) error {
	return fmt.Errorf("environment variable not set: %s", key)
}

func errorSearchResult() ldap.ServerSearchResult {
	return ldap.ServerSearchResult{
		make([]*ldap.Entry, 0),
		[]string{},
		[]ldap.Control{},
		ldap.LDAPResultOperationsError}
}

func getenv(log *zerolog.Logger, key string) string {
	s := os.Getenv(key)
	if strings.Contains(strings.ToUpper(key), "SECRET") ||
		strings.Contains(strings.ToUpper(key), "PASSWORD") ||
		strings.Contains(strings.ToUpper(key), "TOKEN") {
		log.Debug().Str("env", key).Str("value", hide(s)).Send()
	} else {
		log.Debug().Str("env", key).Str("value", s).Send()
	}
	return s
}

func hide(s string) string {
	return strings.Repeat("*", utf8.RuneCountInString(s))
}

func newAttribute(name, value string) *ldap.EntryAttribute {
	return &ldap.EntryAttribute{Name: name, Values: []string{value}}
}

func newKeycloakHandlerConfig(log *zerolog.Logger) (*keycloakHandlerConfig, error) {
	c := &keycloakHandlerConfig{}

	if s := getenv(log, "KEYCLOAK_HOSTNAME"); s == "" {
		return nil, envNotSet("KEYCLOAK_HOSTNAME")
	} else {
		c.keycloakHostname = s
	}

	if s := getenv(log, "KEYCLOAK_PORT"); s == "" {
		c.keycloakPort = 8444
	} else if p, err := strconv.Atoi(s); err != nil {
		return nil, fmt.Errorf("invalid port number: %s", s)
	} else {
		c.keycloakPort = p
	}

	if s := getenv(log, "KEYCLOAK_REALM"); s == "" {
		return nil, envNotSet("KEYCLOAK_REALM")
	} else {
		c.keycloakRealm = s
	}

	if s := getenv(log, "LDAP_DOMAIN"); s == "" {
		return nil, envNotSet("LDAP_DOMAIN")
	} else {
		domain := strings.TrimSuffix(s, ".")
		// Basic validation: domain should not be empty after trimming and should contain valid characters
		if domain == "" || domain == "." {
			return nil, fmt.Errorf("invalid LDAP_DOMAIN: domain is empty or invalid")
		}
		// Check for invalid characters and patterns
		if strings.Contains(domain, "..") || strings.Contains(domain, " ") {
			return nil, fmt.Errorf("invalid LDAP_DOMAIN: contains invalid characters or consecutive dots")
		}
		c.ldapDomain = domain
	}

	if s := getenv(log, "KEYCLOAK_SCHEME"); s != "" {
		c.keycloakScheme = s
	}

	c.keycloakCAFile = getenv(log, "KEYCLOAK_CA_FILE")
	switch strings.ToLower(strings.TrimSpace(getenv(log, "KEYCLOAK_INSECURE_SKIP_VERIFY"))) {
	case "1", "true", "yes":
		c.keycloakInsecureSkipVerify = true
	default:
		c.keycloakInsecureSkipVerify = false
	}

	c.ldapClientID = getenv(log, "KEYCLOAK_LDAP_CLIENT_ID")
	c.ldapClientSecret = getenv(log, "KEYCLOAK_LDAP_CLIENT_SECRET")
	scheme := c.keycloakScheme
	if scheme == "" {
		scheme = "https"
	}
	c.userinfoEndpointURL = fmt.Sprintf("%s://%s:%d/realms/%s/protocol/openid-connect/userinfo",
		scheme, c.keycloakHostname, c.keycloakPort, c.keycloakRealm)

	return c, nil
}

// newTLSConfig builds a *tls.Config from config. If KEYCLOAK_CA_FILE is set, root CAs are loaded from that PEM file.
// If KEYCLOAK_INSECURE_SKIP_VERIFY is true, server certificate verification is skipped (dev/test only).
func newTLSConfig(c *keycloakHandlerConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.keycloakInsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	if c.keycloakCAFile != "" {
		pemBytes, err := os.ReadFile(c.keycloakCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading KEYCLOAK_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no certificates found in KEYCLOAK_CA_FILE: %s", c.keycloakCAFile)
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}

const (
	httpClientTimeout          = 30 * time.Second
	httpClientHandshakeTimeout = 10 * time.Second
)

// newHTTPTransport returns an http.RoundTripper with TLS and timeouts for use by the shared HTTP client and resty.
func newHTTPTransport(c *keycloakHandlerConfig) (http.RoundTripper, error) {
	tlsConfig, err := newTLSConfig(c)
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: httpClientHandshakeTimeout,
	}, nil
}

// sid returns the binary Windows SID (OCTET STRING) for the given id and domain.
// LDAP objectSid is binary; the glauth ldap package uses EntryAttribute.Values []string
// with no separate binary type, so callers pass string(sid(...)) when setting objectSid.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
func sid(id, domain string) []byte {
	d := sha256.Sum256([]byte(domain))
	i := sha256.Sum256([]byte(id))

	b := make([]byte, 1+1+6+5*4)
	b[0] = 1
	b[1] = 5
	binary.BigEndian.PutUint16(b[2:], 0)
	binary.BigEndian.PutUint32(b[4:], 5)
	binary.LittleEndian.PutUint32(b[8:], 21)
	copy(b[12:24], d[:12])
	copy(b[24:28], i[:4])
	return b
}

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
func sidToString(b []byte) string {
	r := b[0]
	n := int(b[1])
	ia := uint64(binary.BigEndian.Uint16(b[2:4]))<<32 +
		uint64(binary.BigEndian.Uint32(b[4:8]))
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("S-%d-%d", r, ia))
	for i := 0; i < n; i++ {
		sa := binary.LittleEndian.Uint32(b[8+4*i : 8+4*i+4])
		sb.WriteString(fmt.Sprintf("-%d", sa))
	}
	return sb.String()
}

func unexpected(msg string) error {
	return fmt.Errorf("unexpected call: %s", msg)
}
