package keycloak

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Role struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type User struct {
	Email      string              `json:"email"`
	FirstName  string              `json:"firstName"`
	ID         string              `json:"id"`
	LastName   string              `json:"lastName"`
	Username   string              `json:"username"`
	Attributes map[string][]string `json:"attributes"`
}

type userinfoResponse struct {
	Sub           string   `json:"sub"`
	PreferredName string   `json:"preferred_username"`
	Email         string   `json:"email"`
	Name          string   `json:"name"`
	GivenName     string   `json:"given_name"`
	FamilyName    string   `json:"family_name"`
	EmailVerified bool     `json:"email_verified"`
	Picture       string   `json:"picture"`
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
	Picture        string                    `json:"picture"`
	Groups         []string                  `json:"groups"`
	Roles          []string                  `json:"roles"`
	RealmRoles     []string                  `json:"realm_roles"`
	RealmAccess    *struct{ Roles []string } `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

func (h *keycloakHandler) keycloakUsersPath() string {
	return "users"
}

func (h *keycloakHandler) keycloakGroupsPath() string {
	return "groups"
}

func (h *keycloakHandler) keycloakRoleUsersPath(roleName string) string {
	return fmt.Sprintf("roles/%s/users", roleName)
}

func (h *keycloakHandler) keycloakUserRoleMappingsCompositePath(userID string) string {
	return fmt.Sprintf("users/%s/role-mappings/realm/composite", userID)
}

func (h *keycloakHandler) keycloakGroupMembersPath(groupID string) string {
	return fmt.Sprintf("groups/%s/members", groupID)
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
	u.Picture = dec.Picture
	u.Groups = dec.Groups
	u.Roles = rolesFromDecode(&dec)
	return nil
}

// rolesFromDecode builds a single list: realm roles as-is, then each client role as "clientId:roleName".
func rolesFromDecode(dec *userinfoDecode) []string {
	var out []string
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

func (h *keycloakHandler) keycloakGet(
	s *session,
	path string,
	result interface{},
) error {
	u := h.config.restAPIEndpoint(path)
	return h.doJSONGet(s, u, "keycloak REST API", result)
}

func (h *keycloakHandler) keycloakUserinfo(s *session) (*userinfoResponse, error) {
	var info userinfoResponse
	if err := h.doJSONGet(s, h.config.userinfoEndpointURL, "userinfo", &info); err != nil {
		return nil, err
	}
	if info.PreferredName == "" {
		info.PreferredName = info.Sub
	}
	if info.PreferredName == "" {
		return nil, errors.New("userinfo: missing preferred_username and sub")
	}
	return &info, nil
}

func (h *keycloakHandler) doJSONGet(s *session, url, logPrefix string, result interface{}) error {
	if h.config == nil {
		return fmt.Errorf("%s: handler config is nil", logPrefix)
	}
	if h.httpClient == nil {
		return fmt.Errorf("%s: HTTP client is nil", logPrefix)
	}
	if s == nil || s.token == nil {
		return fmt.Errorf("%s: no session token", logPrefix)
	}
	h.log.Debug().
		Str("method", "GET").
		Str("url", url).
		Msg(logPrefix + " request")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token.AccessToken)
	resp, err := h.httpClient.Do(req)
	if err != nil {
		h.log.Error().Err(err).Msg(logPrefix + " response")
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		h.log.Error().
			Int("status", resp.StatusCode).
			Str("statusText", resp.Status).
			Str("body", string(body)).
			Msg(logPrefix + " non-200")
		return fmt.Errorf("%s: %s", logPrefix, resp.Status)
	}
	limitedReader := io.LimitReader(resp.Body, maxResponseBodySize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		h.log.Error().Err(err).Msg(logPrefix + " read failed")
		return err
	}
	if len(body) > maxResponseBodySize {
		return fmt.Errorf("%s: response body too large (%d bytes, max %d)", logPrefix, len(body), maxResponseBodySize)
	}
	if err := json.Unmarshal(body, result); err != nil {
		h.log.Error().Err(err).Msg(logPrefix + " decode failed")
		return err
	}
	h.log.Debug().Msg(logPrefix + " response")
	return nil
}
