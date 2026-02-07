# Jellyfin LDAP setup (GLAuth + Keycloak)

Use this when Jellyfin and GLAuth run in the same Kubernetes cluster (e.g. Jellyfin in `media`, GLAuth in `security`). Values below match the default GLAuth config (baseDN `dc=societycell,dc=local`) and the client ID in the `glauth` secret (`glauth-ldap`).

## 1. Exact values (this cluster)

| What | Value |
|------|--------|
| **LDAP Server** | `glauth.security.svc.cluster.local` |
| **LDAP Port** | `3893` |
| **Base DN** | `dc=societycell,dc=local` |
| **LDAP Bind User (bind DN)** | `cn=glauth-ldap,cn=bind,dc=societycell,dc=local` |
| **LDAP Bind User Password** | Client secret from the `glauth` secret (see below) |

Get the bind password from the cluster:

```bash
kubectl get secret glauth -n security -o jsonpath='{.data.KEYCLOAK_LDAP_CLIENT_SECRET}' | base64 -d
echo
```

The bind user is the **Keycloak client** `glauth-ldap`, not a Keycloak user. The plugin uses OAuth2 client credentials (client ID + client secret) to list users.

---

## 2. Jellyfin LDAP settings

Fill the form with these exact values. For **LDAP Bind User Password** use the output of the `kubectl get secret` command above.

| Field | Value |
|-------|--------|
| **LDAP Server** | `glauth.security.svc.cluster.local` |
| **LDAP Port** | `3893` |
| **Secure LDAP** | Off (GLAuth is plain LDAP on 3893) |
| **StartTLS** | Off |
| **LDAP Client Cert / Key / Root CA Path** | Leave empty |
| **Skip SSL/TLS Verification** | N/A (no TLS) |
| **Allow Password Change** | Off (Keycloak manages passwords) |
| **Password Reset Url** | Leave empty or point to Keycloak account console |
| **LDAP Bind User** | `cn=glauth-ldap,cn=bind,dc=societycell,dc=local` |
| **LDAP Bind User Password** | Value from `kubectl get secret glauth -n security -o jsonpath='{.data.KEYCLOAK_LDAP_CLIENT_SECRET}' \| base64 -d` |
| **LDAP Base DN for searches** | `cn=users,dc=societycell,dc=local` |

### Users

| Field | Value |
|-------|--------|
| **LDAP Search Filter** | See the code block below (paste exactly; the character after the first `(` is a single pipe `|` for OR — no backslash). |

Copy this into **LDAP Search Filter** (no backslashes):

```
(|(memberOf=cn=watch-jellyfin,ou=roles,dc=societycell,dc=local)(memberOf=cn=manage-jellyfin,ou=roles,dc=societycell,dc=local))
```
| **LDAP Search Attributes** | `uid, cn, mail, displayName, jpegPhoto` |
| **LDAP Uid Attribute** | `uid` |
| **LDAP Username Attribute** | `cn` |
| **LDAP Password Attribute** | Leave empty (unless you enable password change) |
| **Enable profile image synchronization** | On (if you want to sync user pictures from Keycloak) |
| **LDAP Profile Image Attribute** | `jpegPhoto` |

### Administrators

| Field | Value |
|-------|--------|
| **LDAP Admin Base DN** | `ou=roles,dc=societycell,dc=local` (see Keycloak section for roles) |
| **LDAP Admin Filter** | `(memberOf=cn=manage-jellyfin,ou=roles,dc=societycell,dc=local)` |
| **Enable Admin Filter 'memberUid' mode** | Off |

### Testing

| Field | Value |
|-------|--------|
| **Test Login Name** | A Keycloak username that exists in the realm (e.g. `parthenona` or `test`) |
| **Enable User Creation** | On (recommended: create Jellyfin user on first LDAP login) |
| **Library Access** | As needed |

Save and restart Jellyfin when prompted.

---

## 3. Keycloak configuration

### 3.1 Realm

- Use the realm that GLAuth is configured for. To see it: `kubectl get secret glauth -n security -o jsonpath='{.data.KEYCLOAK_REALM}' | base64 -d && echo`
- Create the client `glauth-ldap` and users in that realm.

### 3.2 Client for GLAuth (bind = Keycloak client, not a user)

The LDAP bind user is the **Keycloak client** `glauth-ldap` (Applications → Clients). The plugin uses OAuth2 client credentials to get a token and call Keycloak’s Admin API for user/group listing.

- **Client ID**: `glauth-ldap` (must match `KEYCLOAK_LDAP_CLIENT_ID` in the glauth secret). Bind DN is `cn=glauth-ldap,cn=bind,dc=societycell,dc=local`.
- **Client authentication**: On.
- **Authorization**: Off (unless you use it).
- **Authentication flow**:
  - **Standard flow**: Off (optional).
  - **Direct access grants**: On (only if this client is also used for user password grant; see below).
  - **Service accounts roles**: On (required for bind).
- **Valid redirect URIs**: not required for LDAP.
- **Client secret**: Stored in the glauth secret as `KEYCLOAK_LDAP_CLIENT_SECRET` and entered in Jellyfin as **LDAP Bind User Password**.

**Service account must be allowed to search users and roles.** In Keycloak: **Clients** → **glauth-ldap** → **Service account roles** → **Assign role** → filter by client **realm-management** → assign **view-users**, **query-users**, **view-realm**. Without these, LDAP bind succeeds but user search returns “Operations Error”.

### 3.3 Optional: client for user password grant

If GLAuth is configured with `KEYCLOAK_LDAP_CLIENT_ID` / `KEYCLOAK_LDAP_CLIENT_SECRET` for **user** logins (password grant), that client must have:

- **Direct access grants**: On.
- Same realm as above.

It can be the same client as the bind user or a different one.

### 3.4 Users

- Create users in the same realm (e.g. **Users** → **Add user**).
- Set **Username** (and optionally **Email**). These map to LDAP `uid` and `mail`; Jellyfin uses them for login and search attributes.

#### 3.4.1 User profile pictures (optional)

To enable profile picture synchronization between Keycloak and Jellyfin:

1. **Configure User Profile in Keycloak:**
   - Go to **Realm Settings** → **User profile**
   - Add or verify the `picture` attribute exists
   - The attribute should be configured to store a URL pointing to the user's profile picture

2. **Set user pictures:**
   - Edit a user in Keycloak (**Users** → select user → **Attributes** tab)
   - Add attribute `picture` with the URL of the user's profile image (e.g., `https://example.com/avatars/user.jpg`)
   - **Security note:** Only use trusted image sources. Consider using a regular expression validator in the user profile configuration to restrict URLs to your domain

3. **Enable in Jellyfin:**
   - Check **Enable profile image synchronization** in the Jellyfin LDAP plugin settings
   - Set **LDAP Profile Image Attribute** to `jpegPhoto`
   - Add `jpegPhoto` to **LDAP Search Attributes**: `uid, cn, mail, displayName, jpegPhoto`

The plugin will automatically expose the Keycloak `picture` attribute as the LDAP `jpegPhoto` attribute, which Jellyfin will use to sync user avatars.

### 3.5 Roles for Jellyfin (search filter and admin filter)

The plugin exposes Keycloak realm roles as LDAP `memberOf` under `ou=roles,dc=<domain>,dc=<tld>`.

- In Keycloak: **Realm roles** → create `watch-jellyfin` (users who can log in) and `manage-jellyfin` (Jellyfin admins).
- Assign **watch-jellyfin** to users who should access Jellyfin; assign **manage-jellyfin** to users who should be Jellyfin administrators.
- **LDAP Search Filter** (who can log in): `(|(memberOf=cn=watch-jellyfin,ou=roles,dc=societycell,dc=local)(memberOf=cn=manage-jellyfin,ou=roles,dc=societycell,dc=local))`
- **LDAP Admin Base DN**: `ou=roles,dc=societycell,dc=local`
- **LDAP Admin Filter**: `(memberOf=cn=manage-jellyfin,ou=roles,dc=societycell,dc=local)`

**Composite/Inherited Roles:** The plugin uses `GET /admin/realms/{realm}/users/{userId}/role-mappings/realm/composite` to get each user's effective roles, so users who inherit `watch-jellyfin` or `manage-jellyfin` through composite roles or group membership are included in search results.

---

## 4. If Jellyfin is outside the cluster

If Jellyfin is not in the same cluster, it cannot use `glauth.security.svc.cluster.local`. Then:

1. Expose GLAuth LDAP (e.g. LoadBalancer/NodePort/Ingress TCP for 3893), or use a port-forward for testing:
   ```bash
   kubectl port-forward -n security svc/glauth 3893:3893
   ```
2. In Jellyfin set:
   - **LDAP Server**: host that reaches that port (e.g. `10.1.1.x`, or `localhost` if using port-forward on the same machine).
   - **LDAP Port**: `3893`.

Keep all other settings (Base DN, Bind User, filters, attributes) as above.

---

## 5. Verify bind and search locally

From the repo root, with GLAuth reachable (e.g. port-forward):

```bash
kubectl port-forward -n security svc/glauth 3893:3893 &
sleep 2
export LDAP_BIND_DN="cn=glauth-ldap,cn=bind,dc=societycell,dc=local"
export LDAP_BIND_PW=$(kubectl get secret glauth -n security -o jsonpath='{.data.KEYCLOAK_LDAP_CLIENT_SECRET}' | base64 -d)
go run ./cmd/verify-ldap-bind/
```

You should see `bind: success` and a list of users (e.g. `parthenona`, `test`). If users search fails with “Operations Error”, add the realm-management roles to the **glauth-ldap** service account (see 3.2).

---

## 6. Quick reference

| Item | Value |
|------|--------|
| **Base DN** | `dc=societycell,dc=local` |
| **User search base** | `cn=users,dc=societycell,dc=local` |
| **Bind DN** | `cn=glauth-ldap,cn=bind,dc=societycell,dc=local` |
| **User login** | Keycloak username = LDAP `uid` / `cn`; password = Keycloak password. |
| **Search filter** | `(&#124;(memberOf=cn=watch-jellyfin,ou=roles,dc=societycell,dc=local)(memberOf=cn=manage-jellyfin,ou=roles,dc=societycell,dc=local))` — create realm roles `watch-jellyfin` and `manage-jellyfin` in Keycloak. |
| **Admin filter** | `(memberOf=cn=manage-jellyfin,ou=roles,dc=societycell,dc=local)` — assign realm role `manage-jellyfin` to Jellyfin admins in Keycloak. |
