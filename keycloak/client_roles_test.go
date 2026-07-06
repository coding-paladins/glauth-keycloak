package keycloak

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientRoleNameFromMemberOfCN(t *testing.T) {
	role, ok := clientRoleNameFromMemberOfCN("jellyfin-admin", "jellyfin")
	assert.True(t, ok)
	assert.Equal(t, "admin", role)

	role, ok = clientRoleNameFromMemberOfCN("jellyfin-user", "jellyfin")
	assert.True(t, ok)
	assert.Equal(t, "user", role)

	_, ok = clientRoleNameFromMemberOfCN("watch-jellyfin", "jellyfin")
	assert.False(t, ok)

	_, ok = clientRoleNameFromMemberOfCN("jellyfin-admin", "")
	assert.False(t, ok)
}

func TestClientRoleCNsFromNames(t *testing.T) {
	assert.Equal(t, []string{"jellyfin-user", "jellyfin-admin"}, clientRoleCNsFromNames("jellyfin", []string{"user", "admin"}))
	assert.Empty(t, clientRoleCNsFromNames("jellyfin", nil))
}

func TestUserClientRoleCNsFromMockKeycloak(t *testing.T) {
	tokenServer := httptest.NewServer(withTestAuth(nil))
	defer tokenServer.Close()
	config := makeHandlerConfigFromURL(t, tokenServer.URL)
	h := makeHandlerWithConfig(config)
	cns, err := h.userClientRoleCNs("alice")
	require.NoError(t, err)
	assert.Equal(t, []string{"ldap-client-user"}, cns)
}
