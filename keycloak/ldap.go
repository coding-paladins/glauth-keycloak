package keycloak

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/glauth/ldap"
	ber "github.com/go-asn1-ber/asn1-ber"
	ldapv3 "github.com/go-ldap/ldap/v3"
)

// extractMemberOfRoleNames parses an LDAP filter like (|(memberOf=cn=role1,ou=roles,dc=...)(memberOf=cn=role2,ou=roles,dc=...))
// and returns the list of role names (cn values from clauses whose DN contains "ou=roles").
func extractMemberOfRoleNames(filter string) []string {
	return extractMemberOfNames(filter, "ou=roles")
}

// extractMemberOfGroupNames parses an LDAP filter like (|(memberOf=cn=group1,cn=groups,dc=...)(memberOf=cn=group2,cn=groups,dc=...))
// and returns the list of group names (cn values from clauses whose DN contains "groups").
func extractMemberOfGroupNames(filter string) []string {
	return extractMemberOfNames(filter, "groups")
}

func extractMemberOfNames(filter string, dnContains string) []string {
	filterPacket, err := ldap.CompileFilter(filter)
	if err != nil {
		return nil
	}
	dnContainsLower := strings.ToLower(dnContains)
	seen := make(map[string]bool)
	var names []string
	var walk func(p *ber.Packet)
	walk = func(p *ber.Packet) {
		switch ldap.FilterMap[p.Tag] {
		case "And", "Or":
			for _, child := range p.Children {
				walk(child)
			}
		case "Not":
			if len(p.Children) == 1 {
				walk(p.Children[0])
			}
		case "Equality Match":
			if len(p.Children) != 2 {
				return
			}
			attr, ok := p.Children[0].Value.(string)
			if !ok || !strings.EqualFold(attr, "memberOf") {
				return
			}
			value, ok := p.Children[1].Value.(string)
			if !ok {
				return
			}
			if !strings.Contains(strings.ToLower(value), dnContainsLower) {
				return
			}
			parsed, err := ldapv3.ParseDN(value)
			if err != nil || parsed == nil || len(parsed.RDNs) == 0 {
				return
			}
			for _, attr := range parsed.RDNs[0].Attributes {
				if strings.EqualFold(attr.Type, "cn") {
					name := strings.TrimSpace(attr.Value)
					if name == "" || seen[name] {
						return
					}
					seen[name] = true
					names = append(names, name)
					return
				}
			}
		}
	}
	walk(filterPacket)
	return names
}

// realmRolesFromUserinfo returns all role names from the userinfo response (Roles is filled from any Keycloak role claim).
func realmRolesFromUserinfo(info *userinfoResponse) []string {
	if info == nil || len(info.Roles) == 0 {
		return nil
	}
	return info.Roles
}

// groupPathToCN turns a Keycloak group path (e.g. "/admins" or "/parent/child") into an LDAP cn value (last segment).
func groupPathToCN(path string) string {
	path = strings.TrimPrefix(strings.TrimSpace(path), "/")
	if path == "" {
		return ""
	}
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	return path
}

// parseFirstCNValueFromBindDNWithSuffix extracts the first RDN's cn value (unescaped) from bindDN
// when bindDN ends with suffix (e.g. ",cn=users,dc=example,dc=com"). suffix must include the leading comma.
func parseFirstCNValueFromBindDNWithSuffix(bindDN, suffix string) (value string, ok bool) {
	if len(bindDN) < len(suffix) || !strings.EqualFold(bindDN[len(bindDN)-len(suffix):], suffix) {
		return "", false
	}
	parsed, err := ldapv3.ParseDN(bindDN)
	if err != nil || parsed == nil || len(parsed.RDNs) == 0 {
		return "", false
	}
	suffixDN := strings.TrimPrefix(suffix, ",")
	parsedSuffix, err := ldapv3.ParseDN(suffixDN)
	if err != nil || parsedSuffix == nil {
		return "", false
	}
	if len(parsed.RDNs) != len(parsedSuffix.RDNs)+1 {
		return "", false
	}
	offset := len(parsed.RDNs) - len(parsedSuffix.RDNs)
	for i := 0; i < len(parsedSuffix.RDNs); i++ {
		entryRDN := parsed.RDNs[i+offset].String()
		suffixRDN := parsedSuffix.RDNs[i].String()
		if !strings.EqualFold(entryRDN, suffixRDN) {
			return "", false
		}
	}
	first := parsed.RDNs[0]
	for _, attr := range first.Attributes {
		if strings.EqualFold(attr.Type, "cn") {
			if strings.TrimSpace(attr.Value) == "" {
				return "", false
			}
			return attr.Value, true
		}
	}
	return "", false
}

func parseUsernameFromUserBindDN(bindDN string, baseDNUsers string) (username string, ok bool) {
	return parseFirstCNValueFromBindDNWithSuffix(bindDN, ","+baseDNUsers)
}

func parseCommonNameFromDN(dn string) (string, bool) {
	parsed, err := ldapv3.ParseDN(dn)
	if err != nil || parsed == nil || len(parsed.RDNs) == 0 {
		return "", false
	}
	first := parsed.RDNs[0]
	for _, attr := range first.Attributes {
		if strings.EqualFold(attr.Type, "cn") {
			cn := strings.TrimSpace(attr.Value)
			if cn == "" {
				return "", false
			}
			return cn, true
		}
	}
	return "", false
}

// escapeRDNValue escapes an attribute value for use in a DN (RFC 4514).
// Escapes: \ , # + ; < > = ", leading/trailing spaces, and control characters.
func escapeRDNValue(value string) string {
	if value == "" {
		return value
	}
	var b strings.Builder
	for i, r := range value {
		switch r {
		case '\\', ',', '#', '+', ';', '<', '>', '=', '"':
			b.WriteRune('\\')
			b.WriteRune(r)
		case ' ':
			if i == 0 || i == len(value)-1 {
				b.WriteString("\\ ")
			} else {
				b.WriteRune(' ')
			}
		default:
			if r < 32 || r == 127 {
				b.WriteString(fmt.Sprintf("\\%02x", r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func newAttribute(name, value string) *ldap.EntryAttribute {
	return &ldap.EntryAttribute{Name: name, Values: []string{value}}
}

// sid returns the binary Windows SID (OCTET STRING) for the given id and domain.
// LDAP objectSid is binary; the glauth ldap package uses EntryAttribute.Values []string
// with no separate binary type, so callers pass string(sid(...)) when setting objectSid.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
func sid(id, domain string) []byte {
	d := sha256.Sum256([]byte(domain))
	i := sha256.Sum256([]byte(id))

	b := make([]byte, 1+1+6+5*4)
	b[0] = 1
	b[1] = 5
	binary.BigEndian.PutUint16(b[2:], 0)
	binary.BigEndian.PutUint32(b[4:], 5)
	binary.LittleEndian.PutUint32(b[8:], 21)
	copy(b[12:24], d[:12])
	copy(b[24:28], i[:4])
	return b
}

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
func sidToString(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	n := int(b[1])
	if n < 0 || len(b) < 8+4*n {
		return ""
	}
	r := b[0]
	ia := uint64(binary.BigEndian.Uint16(b[2:4]))<<32 +
		uint64(binary.BigEndian.Uint32(b[4:8]))
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("S-%d-%d", r, ia))
	for i := 0; i < n; i++ {
		sa := binary.LittleEndian.Uint32(b[8+4*i : 8+4*i+4])
		sb.WriteString(fmt.Sprintf("-%d", sa))
	}
	return sb.String()
}

func unexpected(msg string) error {
	return fmt.Errorf("unexpected call: %s", msg)
}
