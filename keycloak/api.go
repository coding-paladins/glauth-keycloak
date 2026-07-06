package keycloak

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

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
	Groups        []string `json:"groups"`
}

func (h *keycloakHandler) keycloakUsersPath() string {
	return "users"
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
