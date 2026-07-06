# Jellyfin LDAP setup (GLAuth + Keycloak client roles)

GLAuth talks to Keycloak over the **Admin API** using the `jellyfin` service account. No Keycloak Groups, no userinfo mappers, no custom client scopes.

## Keycloak checklist

1. Create client **`jellyfin`**
   - Client authentication: On
   - Service accounts: On
   - Direct access grants: On (user login via password grant)

2. Create **client roles** on `jellyfin` (e.g. `user`, `admin`)

3. Assign roles to users (**Users** → user → **Role mapping** → `jellyfin`). Inherited roles (e.g. via groups) are included.

4. **Service account roles** (`realm-management`):
   - `view-users`, `query-users`
   - `view-clients`, `query-clients`

That is all.

## How authorization works

| Action | Mechanism |
|--------|-----------|
| Jellyfin LDAP bind | OAuth client credentials (`jellyfin` + secret) |
| User search (`memberOf` filter) | Admin API: effective client roles per user |
| User login | Password grant + Admin API: user must have ≥1 effective role on `jellyfin` |
| `memberOf` on user entry | Effective client roles → `cn={clientId}-{role},cn=groups,...` |

LDAP `cn=groups,...` is naming only — values are client roles, not Keycloak Groups.

## Jellyfin LDAP settings

| Field | Value |
|-------|--------|
| **LDAP Server** | `glauth-jellyfin.media.svc.cluster.local` |
| **LDAP Port** | `3893` |
| **LDAP Bind User** | `cn=jellyfin,cn=bind,dc=societycell,dc=local` |
| **LDAP Bind User Password** | `jellyfin` client secret |
| **LDAP Base DN** | `cn=users,dc=societycell,dc=local` |
| **LDAP Search Filter** | `(\|(memberOf=cn=jellyfin-user,cn=groups,dc=societycell,dc=local)(memberOf=cn=jellyfin-admin,cn=groups,dc=societycell,dc=local))` |
| **LDAP Admin Base DN** | `cn=groups,dc=societycell,dc=local` |
| **LDAP Admin Filter** | `(memberOf=cn=jellyfin-admin,cn=groups,dc=societycell,dc=local)` |

Role names in filters (`jellyfin-user`, `jellyfin-admin`) must match `{clientId}-{role}` where `role` is the Keycloak client role name.

## Environment variables (GLAuth secret)

| Variable | Example |
|----------|---------|
| `KEYCLOAK_HOSTNAME` | `keycloak.security.svc.cluster.local` |
| `KEYCLOAK_PORT` | `8080` |
| `KEYCLOAK_REALM` | `societycell` |
| `KEYCLOAK_SCHEME` | `http` |
| `LDAP_DOMAIN` | `societycell.local` |
| `KEYCLOAK_LDAP_CLIENT_ID` | `jellyfin` |
| `KEYCLOAK_LDAP_CLIENT_SECRET` | *(client secret)* |
