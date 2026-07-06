package keycloak

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserinfoResponseUnmarshalJSONInvalid(t *testing.T) {
	var u userinfoResponse
	err := json.Unmarshal([]byte("not valid json"), &u)
	assert.Error(t, err)
}

func TestUserinfoResponseUnmarshalJSONGroups(t *testing.T) {
	var u userinfoResponse
	err := json.Unmarshal([]byte(`{
		"sub": "774bcdb5-1742-4143-8ad5-abdbd80bf842",
		"preferred_username": "admin",
		"groups": ["amp-admins", "amp-moderators", "amp-restricted-access"]
	}`), &u)
	require.NoError(t, err)
	assert.Equal(t, "admin", u.PreferredName)
	assert.Equal(t, []string{"amp-admins", "amp-moderators", "amp-restricted-access"}, u.Groups)
}

func TestUserinfoResponseUnmarshalJSONIgnoresRoles(t *testing.T) {
	var u userinfoResponse
	err := json.Unmarshal([]byte(`{
		"preferred_username": "bob",
		"groups": ["team-a"],
		"realm_access": {"roles": ["admin", "default-roles-societycell"]}
	}`), &u)
	require.NoError(t, err)
	assert.Equal(t, []string{"team-a"}, u.Groups)
}
