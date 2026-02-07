# Jellyfin LDAP Picture Troubleshooting

## Test Results

✅ **LDAP Server is working correctly** - The `jpegPhoto` attribute is being returned for users with pictures in Keycloak.

Test output shows:
- User `parthenona` has jpegPhoto: `https://avatars.githubusercontent.com/u/20465224?v=4`
- User `test` does not have a picture set

## Jellyfin Configuration Checklist

To enable profile pictures in Jellyfin, verify ALL of these settings:

### 1. LDAP Plugin Settings → Users Section

Check these exact settings in Jellyfin LDAP plugin:

| Setting | Required Value |
|---------|---------------|
| **LDAP Search Attributes** | Must include `jpegPhoto` (add it to the existing list) |
| | Example: `uid, cn, mail, displayName, jpegPhoto` |
| **Enable profile image synchronization** | ☑ **Checked (ON)** |
| **LDAP Profile Image Attribute** | `jpegPhoto` |

### 2. How to Update Jellyfin Settings

1. **Go to Jellyfin Admin Dashboard**
   - Navigate to: Dashboard → Plugins → LDAP Authentication

2. **Edit the LDAP Server Configuration**
   - Click on your LDAP server entry
   - Scroll to the "Users" section

3. **Update LDAP Search Attributes**
   - Current: `uid, cn, mail, displayName`
   - **Change to**: `uid, cn, mail, displayName, jpegPhoto`

4. **Enable Profile Image Sync**
   - Find: "Enable profile image synchronization"
   - **Check this box**

5. **Set Profile Image Attribute**
   - Find: "LDAP Profile Image Attribute"
   - Enter: `jpegPhoto`

6. **Save and Restart**
   - Click "Save"
   - Restart Jellyfin when prompted

### 3. Force Re-sync Existing Users

After updating the configuration, Jellyfin needs to re-sync the user data:

**Option A: Delete and Re-add Users (Recommended)**
1. Dashboard → Users
2. Delete the LDAP user (e.g., `parthenona`)
3. Log in again with LDAP credentials
4. Jellyfin will create the user fresh with the picture

**Option B: Manual API Call (Advanced)**
```bash
# Force user profile sync via Jellyfin API
curl -X POST "http://jellyfin-url/Users/{userId}/Authenticate" \
  -H "Authorization: MediaBrowser Token=YOUR_API_KEY"
```

**Option C: Wait for Next Login**
- The picture should sync on the user's next login

### 4. Verify Picture URL is Accessible

Make sure the picture URL is accessible from Jellyfin:

```bash
# Test from Jellyfin server
curl -I https://avatars.githubusercontent.com/u/20465224?v=4
```

Should return `HTTP/2 200` or `HTTP/1.1 200 OK`

### 5. Check Jellyfin Logs

If pictures still don't show, check Jellyfin logs:

```bash
# In Jellyfin container/system
tail -f /var/log/jellyfin/log_*.txt
```

Look for:
- LDAP authentication messages
- Picture download errors
- SSL/TLS errors (if picture URLs are HTTPS)

## Common Issues

### Issue 1: Pictures Not Showing After Configuration
**Solution**: Delete the LDAP user from Jellyfin and have them log in again. Jellyfin caches user data.

### Issue 2: Some Pictures Work, Others Don't
**Cause**: The picture URL might not be accessible from Jellyfin's network.
**Solution**: Ensure Jellyfin can reach the picture URLs (check firewall, DNS, SSL certificates).

### Issue 3: HTTP Pictures Don't Load
**Cause**: Jellyfin might block mixed content (HTTPS page loading HTTP images).
**Solution**: Use HTTPS URLs for pictures.

### Issue 4: Large Pictures Timeout
**Cause**: Picture files might be too large.
**Solution**: Use optimized/thumbnail versions of images (< 1MB recommended).

## Adding Pictures to More Users in Keycloak

For users without pictures (like `test`):

1. **Login to Keycloak Admin Console**
   - URL: `http://keycloak.security.svc.cluster.local:8080` (or your Keycloak URL)
   - Realm: `societycell`

2. **Navigate to the User**
   - Users → Search for user → Click on username

3. **Add Picture Attribute**
   - Click "Attributes" tab
   - Click "Add attribute"
   - Key: `picture`
   - Value: `https://example.com/path/to/avatar.jpg` (use a real, accessible URL)
   - Click "Save"

4. **Test in Jellyfin**
   - Delete the user from Jellyfin (Dashboard → Users)
   - Log in again with LDAP
   - Picture should now appear

## Next Steps

1. ✅ Verify LDAP is returning jpegPhoto (DONE - working!)
2. ⚠️  Update Jellyfin LDAP plugin settings (follow checklist above)
3. ⚠️  Delete and re-add LDAP users in Jellyfin
4. ⚠️  Verify pictures appear in Jellyfin UI

Need help with any specific step? Let me know!
