package keycloak

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

type keycloakClient struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
}

type keycloakRole struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// clientRolePrefix returns "{clientID}-" for LDAP memberOf / groups claim names (e.g. jellyfin-admin).
func clientRolePrefix(clientID string) string {
	if clientID == "" {
		return ""
	}
	return clientID + "-"
}

// clientRoleNameFromMemberOfCN maps LDAP memberOf cn (e.g. jellyfin-admin) to Keycloak client role (admin).
func clientRoleNameFromMemberOfCN(cn, clientID string) (string, bool) {
	prefix := clientRolePrefix(clientID)
	if prefix == "" || cn == "" {
		return "", false
	}
	if !strings.HasPrefix(strings.ToLower(cn), strings.ToLower(prefix)) {
		return "", false
	}
	role := cn[len(prefix):]
	if role == "" {
		return "", false
	}
	return role, true
}

func clientRoleCNsFromNames(clientID string, roleNames []string) []string {
	prefix := clientRolePrefix(clientID)
	cns := make([]string, 0, len(roleNames))
	for _, name := range roleNames {
		name = strings.TrimSpace(name)
		if name != "" {
			cns = append(cns, prefix+name)
		}
	}
	return cns
}

func (h *keycloakHandler) keycloakClientsQueryPath() string {
	return fmt.Sprintf("clients?clientId=%s", url.QueryEscape(h.config.ldapClientID))
}

func (h *keycloakHandler) keycloakClientRoleUsersPath(clientUUID, roleName string) string {
	return fmt.Sprintf("clients/%s/roles/%s/users", clientUUID, url.PathEscape(roleName))
}

func (h *keycloakHandler) keycloakUserByUsernamePath(username string) string {
	return fmt.Sprintf("users?username=%s&exact=true", url.QueryEscape(username))
}

func (h *keycloakHandler) keycloakUserClientRolesPath(userID, clientUUID string) string {
	return fmt.Sprintf("users/%s/role-mappings/clients/%s", userID, clientUUID)
}

func (h *keycloakHandler) keycloakUserClientRolesCompositePath(userID, clientUUID string) string {
	return fmt.Sprintf("users/%s/role-mappings/clients/%s/composite", userID, clientUUID)
}

func (h *keycloakHandler) keycloakClientUUID(s *session) (string, error) {
	if h.clientUUID != "" {
		return h.clientUUID, nil
	}
	clients := &[]keycloakClient{}
	if err := h.keycloakGet(s, h.keycloakClientsQueryPath(), clients); err != nil {
		return "", err
	}
	for _, c := range *clients {
		if strings.EqualFold(c.ClientID, h.config.ldapClientID) && c.ID != "" {
			h.clientUUID = c.ID
			return c.ID, nil
		}
	}
	return "", fmt.Errorf("keycloak client %q not found", h.config.ldapClientID)
}

func (h *keycloakHandler) serviceAccountSession() (*session, error) {
	h.serviceMu.Lock()
	defer h.serviceMu.Unlock()
	bindDN := fmt.Sprintf("cn=%s,%s", escapeRDNValue(h.config.ldapClientID), h.baseDNBindUsers)
	if h.serviceSession != nil && h.serviceSession.token != nil && h.serviceSession.token.Valid() {
		h.serviceSession.lastActivity = time.Now()
		return h.serviceSession, nil
	}
	s := &session{}
	if err := s.open(h.log, h.tokenEndpoint(), h.config.ldapClientID, h.config.ldapClientSecret, bindDN, h.httpClient); err != nil {
		return nil, err
	}
	h.serviceSession = s
	return s, nil
}

func (h *keycloakHandler) keycloakUserByUsername(s *session, username string) (*User, error) {
	users := &[]User{}
	if err := h.keycloakGet(s, h.keycloakUserByUsernamePath(username), users); err != nil {
		return nil, err
	}
	for _, u := range *users {
		if strings.EqualFold(u.Username, username) {
			return &u, nil
		}
	}
	return nil, fmt.Errorf("keycloak user %q not found", username)
}

func (h *keycloakHandler) userClientRoleNames(s *session, userID string) ([]string, error) {
	clientUUID, err := h.keycloakClientUUID(s)
	if err != nil {
		return nil, err
	}
	roles := &[]keycloakRole{}
	path := h.keycloakUserClientRolesCompositePath(userID, clientUUID)
	if err := h.keycloakGet(s, path, roles); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(*roles))
	for _, r := range *roles {
		if r.Name != "" {
			names = append(names, r.Name)
		}
	}
	return names, nil
}

// userClientRoleCNs returns LDAP memberOf cn values (e.g. jellyfin-user) via Admin API.
func (h *keycloakHandler) userClientRoleCNs(username string) ([]string, error) {
	s, err := h.serviceAccountSession()
	if err != nil {
		return nil, err
	}
	user, err := h.keycloakUserByUsername(s, username)
	if err != nil {
		return nil, err
	}
	roleNames, err := h.userClientRoleNames(s, user.ID)
	if err != nil {
		return nil, err
	}
	return clientRoleCNsFromNames(h.config.ldapClientID, roleNames), nil
}

func (h *keycloakHandler) usersWithClientRole(s *session, roleName string) ([]User, error) {
	allUsers := &[]User{}
	if err := h.keycloakGet(s, h.keycloakUsersPath(), allUsers); err != nil {
		return nil, err
	}
	matched := make([]User, 0)
	for _, user := range *allUsers {
		roleNames, err := h.userClientRoleNames(s, user.ID)
		if err != nil {
			h.log.Debug().Err(err).Str("username", user.Username).Str("roleName", roleName).Msg("keycloak get user client roles failed")
			continue
		}
		for _, name := range roleNames {
			if strings.EqualFold(name, roleName) {
				matched = append(matched, user)
				break
			}
		}
	}
	return matched, nil
}
