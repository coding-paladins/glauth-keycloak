# glauth-keycloak

GLAuth plugin that allows Keycloak to operate as an identity provider.

## User login (LDAP bind as user)

End-user login over LDAP is supported so that clients (e.g. Jellyfin) can bind
with a user's DN and password. The plugin validates the password using Keycloak's
Resource Owner Password Credentials (password) grant.

### Configuration

Set these optional environment variables so user bind is enabled:

- `KEYCLOAK_LDAP_CLIENT_ID` — Keycloak confidential client ID (must have **Direct access grants** enabled).
- `KEYCLOAK_LDAP_CLIENT_SECRET` — Client secret.

If both are set, binds with a **user** DN (see below) are treated as user login;
otherwise only service-account bind is allowed.

### Bind DN for user login

- **User bind**: `cn=<username>,cn=users,dc=<domain>,dc=...`  
  The first `cn` value is used as the Keycloak username; the bind password is
  validated via Keycloak's token endpoint (password grant).  
  Example: `cn=johndoe,cn=users,dc=example,dc=com` with the user's password.

- **Service account bind** (unchanged): `cn=<clientId>,cn=bind,dc=<domain>,dc=...`  
  Used for LDAP search with Keycloak Admin API; password is the client secret.
