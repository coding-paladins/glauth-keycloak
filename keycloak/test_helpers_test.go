package keycloak

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

var nopLogger = zerolog.Nop()

var attributes3 = []string{
	"sAMAccountName",
	"description",
	"objectSid",
}

var attributes9 = []string{
	"sAMAccountName",
	"userPrincipalName",
	"description",
	"givenName",
	"sn",
	"mail",
	"userAccountControl",
	"lockoutTime",
	"objectSid",
}

func init() {
	allowNilConnectionForTests = true
}

func makeHandlerConfigFromURL(t *testing.T, serverURL string) *keycloakHandlerConfig {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	require.NoError(t, err)
	port := 443
	if parsed.Port() != "" {
		port, _ = strconv.Atoi(parsed.Port())
	}
	scheme := "https"
	if parsed.Scheme != "" {
		scheme = parsed.Scheme
	}
	return &keycloakHandlerConfig{
		keycloakHostname:    parsed.Hostname(),
		keycloakPort:        port,
		keycloakRealm:       "test",
		keycloakScheme:      scheme,
		ldapDomain:          "example.com",
		ldapClientID:        "ldap-client",
		ldapClientSecret:    "secret",
		userinfoEndpointURL: serverURL + "/userinfo",
	}
}

func makeHandlerWithConfig(c *keycloakHandlerConfig) *keycloakHandler {
	b := "dc=example,dc=com"
	if c.ldapDomain != "" {
		parts := strings.Split(c.ldapDomain, ".")
		b = "dc=" + strings.Join(parts, ",dc=")
	}
	var transport http.RoundTripper
	if c.keycloakScheme != "http" {
		transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if transport != nil {
		httpClient.Transport = transport
	}
	return &keycloakHandler{
		config:          c,
		baseDNUsers:     "cn=users," + b,
		baseDNGroups:    "cn=groups," + b,
		baseDNBindUsers: "cn=bind," + b,
		httpClient:      httpClient,
		sessions:        map[string]*session{"default": {}},
		log:             &nopLogger,
	}
}
