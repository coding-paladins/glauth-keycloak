# Verify LDAP Picture Attribute

This tool verifies that user profile pictures from Keycloak are being exposed correctly through the LDAP interface as the `jpegPhoto` attribute.

## Usage

### With Port Forward

```bash
# 1. Start port-forward to GLAuth
kubectl port-forward -n security svc/glauth 3893:3893 &

# 2. Get credentials from secret
export LDAP_BIND_DN="cn=glauth-ldap,cn=bind,dc=societycell,dc=local"
export LDAP_BIND_PW=$(kubectl get secret glauth -n security -o jsonpath='{.data.KEYCLOAK_LDAP_CLIENT_SECRET}' | base64 -d)

# 3. Run the test
go run ./cmd/verify-ldap-picture
```

### Quick Test Script

```bash
./test-picture.sh
```

This automatically:
- Gets credentials from Kubernetes secret
- Sets up port-forward
- Runs the verification tool
- Shows which users have pictures

## Expected Output

```
bind: success

users search (cn=users,dc=societycell,dc=local): 2 entries
----------------------------------------

User: cn=parthenona,cn=users,dc=societycell,dc=local
  cn:          parthenona
  uid:         parthenona
  mail:        begemot122@gmail.com
  jpegPhoto:   https://avatars.githubusercontent.com/u/20465224?v=4

User: cn=test,cn=users,dc=societycell,dc=local
  cn:          test
  uid:         test
  mail:        test@test
  jpegPhoto:   (not set)

----------------------------------------
✓ Found users with jpegPhoto attribute
```

## Troubleshooting

### No users have pictures

If you see `✗ No users have jpegPhoto attribute set`, you need to add pictures in Keycloak:

1. Go to Keycloak Admin Console
2. Select your realm (e.g., `societycell`)
3. Navigate to: Users → Select a user → Attributes tab
4. Add attribute:
   - Key: `picture`
   - Value: `https://example.com/avatar.jpg` (use a real URL)
5. Click "Save"
6. Run the test again

### Connection refused

Make sure:
- GLAuth pod is running: `kubectl get pods -n security`
- Port-forward is active: `kubectl port-forward -n security svc/glauth 3893:3893`
- You're running the test from the same machine as port-forward

### Bind failed

Check:
- Secret exists: `kubectl get secret glauth -n security`
- Client ID and secret are correct
- The Keycloak client has the required permissions (view-users, query-users)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LDAP_URL` | `ldap://127.0.0.1:3893` | LDAP server URL |
| `LDAP_BIND_DN` | (required) | Bind DN (service account) |
| `LDAP_BIND_PW` | (required) | Bind password (client secret) |
| `LDAP_BASE_DN` | `dc=societycell,dc=local` | Base DN for searches |

## See Also

- [Jellyfin LDAP Setup](../../docs/jellyfin-ldap-setup.md) - Main setup guide
- [Picture Troubleshooting](../../docs/jellyfin-picture-troubleshooting.md) - Jellyfin-specific troubleshooting
