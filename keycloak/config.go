package keycloak

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog"
)

const (
	httpClientTimeout          = 30 * time.Second
	httpClientHandshakeTimeout = 10 * time.Second
)

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

func envNotSet(key string) error {
	return fmt.Errorf("environment variable not set: %s", key)
}

func requireEnv(log *zerolog.Logger, key string) (string, error) {
	s := getenv(log, key)
	if s == "" {
		return "", envNotSet(key)
	}
	return s, nil
}

func getOptionalPort(log *zerolog.Logger, key string, defaultPort int) (int, error) {
	s := getenv(log, key)
	if s == "" {
		return defaultPort, nil
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port number: %s", s)
	}
	return p, nil
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

func newKeycloakHandlerConfig(log *zerolog.Logger) (*keycloakHandlerConfig, error) {
	c := &keycloakHandlerConfig{}

	hostname, err := requireEnv(log, "KEYCLOAK_HOSTNAME")
	if err != nil {
		return nil, err
	}
	c.keycloakHostname = hostname

	port, err := getOptionalPort(log, "KEYCLOAK_PORT", 8444)
	if err != nil {
		return nil, err
	}
	c.keycloakPort = port

	realm, err := requireEnv(log, "KEYCLOAK_REALM")
	if err != nil {
		return nil, err
	}
	c.keycloakRealm = realm

	domainRaw, err := requireEnv(log, "LDAP_DOMAIN")
	if err != nil {
		return nil, err
	}
	domain := strings.TrimSuffix(domainRaw, ".")
	if domain == "" || domain == "." {
		return nil, fmt.Errorf("invalid LDAP_DOMAIN: domain is empty or invalid")
	}
	if strings.Contains(domain, "..") || strings.Contains(domain, " ") {
		return nil, fmt.Errorf("invalid LDAP_DOMAIN: contains invalid characters or consecutive dots")
	}
	c.ldapDomain = domain

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

// newHTTPTransport returns an http.RoundTripper with TLS and timeouts for use by the HTTP client.
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
