package keycloak

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserinfoResponseUnmarshalJSONInvalid(t *testing.T) {
	var u userinfoResponse
	err := u.UnmarshalJSON([]byte("not valid json"))
	assert.Error(t, err)
}

func TestUserinfoResponseUnmarshalJSONRolesFromRealmAccessOnly(t *testing.T) {
	var u userinfoResponse
	err := json.Unmarshal([]byte(`{"realm_access":{"roles":["r1","r2"]}}`), &u)
	require.NoError(t, err)
	assert.Equal(t, []string{"r1", "r2"}, u.Roles)
}

func TestUserinfoResponseUnmarshalJSONRolesFromRealmRolesOnly(t *testing.T) {
	var u userinfoResponse
	err := json.Unmarshal([]byte(`{"realm_roles":["a","b"]}`), &u)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, u.Roles)
}

func TestUserinfoResponseUnmarshalJSONRolesFromRolesOnly(t *testing.T) {
	var u userinfoResponse
	err := json.Unmarshal([]byte(`{"roles":["x"]}`), &u)
	require.NoError(t, err)
	assert.Equal(t, []string{"x"}, u.Roles)
}

func TestUserinfoResponseUnmarshalJSONResourceAccessEmptyClientIDSkipped(t *testing.T) {
	// rolesFromDecode skips resource_access entries with empty or whitespace clientID
	var u userinfoResponse
	err := json.Unmarshal([]byte(`{"realm_access":{"roles":[]},"resource_access":{"":{"roles":["x"]},"  ":{"roles":["y"]},"client":{"roles":["z"]}}}`), &u)
	require.NoError(t, err)
	assert.Contains(t, u.Roles, "client:z")
	assert.Len(t, u.Roles, 1)
}

func TestUserinfoResponseUnmarshalJSONResourceAccessEmptyRoleSkipped(t *testing.T) {
	var u userinfoResponse
	err := json.Unmarshal([]byte(`{"realm_access":{"roles":["r1"]},"resource_access":{"c1":{"roles":["","role1"]}}}`), &u)
	require.NoError(t, err)
	assert.Contains(t, u.Roles, "r1")
	assert.Contains(t, u.Roles, "c1:role1")
	assert.Len(t, u.Roles, 2)
}

func TestUserinfoResponseUnmarshalJSONRealmRoleEmptySkipped(t *testing.T) {
	var u userinfoResponse
	err := json.Unmarshal([]byte(`{"realm_access":{"roles":["","a",""]}}`), &u)
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, u.Roles)
}
