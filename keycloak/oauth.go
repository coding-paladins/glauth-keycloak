package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

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
		EndpointParams: url.Values{},
	}

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
