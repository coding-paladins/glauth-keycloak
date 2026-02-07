package keycloak

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/glauth/ldap"
	ldapv3 "github.com/go-ldap/ldap/v3"
)

var rootDSEAttributes = []string{
	"configurationNamingContext",
	"currentTime",
	"defaultNamingContext",
	"dnsHostName",
	"domainControllerFunctionality",
	"domainFunctionality",
	"dsServiceName",
	"forestFunctionality",
	"highestCommittedUSN",
	"isGlobalCatalogReady",
	"isSynchronized",
	"ldapServiceName",
	"namingContexts",
	"rootDomainNamingContext",
	"schemaNamingContext",
	"serverName",
	"subschemaSubentry",
	"supportedCapabilities",
	"supportedControl",
	"supportedLDAPPolicies",
	"supportedLDAPVersion",
	"supportedSASLMechanisms",
}

func validateSearchRequestConstraints(req ldap.SearchRequest) error {
	if req.DerefAliases != ldap.NeverDerefAliases || req.TimeLimit != 0 || req.TypesOnly {
		return unexpected(fmt.Sprintf("deferAliases: \"%s\", sizeLimit: %d, timeLimit: %d, typesOnly: %t",
			ldap.DerefMap[req.DerefAliases], req.SizeLimit, req.TimeLimit, req.TypesOnly))
	}
	return nil
}

type searchHandlerResult struct {
	result ldap.ServerSearchResult
	err    error
}

func (h *keycloakHandler) tryMemberOfRolesSearch(sess *session, req ldap.SearchRequest) (searchHandlerResult, bool) {
	rolesBaseDN := "ou=roles," + strings.TrimPrefix(h.baseDNUsers, "cn=users,")
	roleNames := memberOfRolesSearchRoleNames(req)
	if len(roleNames) == 0 || req.Scope != ldap.ScopeWholeSubtree {
		return searchHandlerResult{}, false
	}
	if !strings.EqualFold(req.BaseDN, h.baseDNUsers) && !strings.EqualFold(req.BaseDN, rolesBaseDN) {
		return searchHandlerResult{}, false
	}
	return h.executeSearchWithFilter(req, func() (ldap.ServerSearchResult, error) {
		return h.usersByMemberOfRolesSearchResult(sess, roleNames)
	}), true
}

func (h *keycloakHandler) tryMemberOfGroupsSearch(sess *session, req ldap.SearchRequest) (searchHandlerResult, bool) {
	groupNames := extractMemberOfGroupNames(req.Filter)
	if len(groupNames) == 0 {
		return searchHandlerResult{}, false
	}
	if !strings.EqualFold(req.BaseDN, h.baseDNUsers) || req.Scope != ldap.ScopeWholeSubtree {
		return searchHandlerResult{}, false
	}
	return h.executeSearchWithFilter(req, func() (ldap.ServerSearchResult, error) {
		return h.usersByMemberOfGroupsSearchResult(sess, groupNames)
	}), true
}

func (h *keycloakHandler) tryUsersSearch(sess *session, req ldap.SearchRequest) (searchHandlerResult, bool) {
	if !strings.EqualFold(req.BaseDN, h.baseDNUsers) || req.Scope != ldap.ScopeWholeSubtree {
		return searchHandlerResult{}, false
	}
	return h.executeSearchWithFilter(req, func() (ldap.ServerSearchResult, error) {
		return h.usersSearchResult(sess)
	}), true
}

func (h *keycloakHandler) tryGroupsSearch(sess *session, req ldap.SearchRequest) (searchHandlerResult, bool) {
	if !strings.EqualFold(req.BaseDN, h.baseDNGroups) || req.Scope != ldap.ScopeWholeSubtree {
		return searchHandlerResult{}, false
	}
	return h.executeSearchWithFilter(req, func() (ldap.ServerSearchResult, error) {
		return h.groupsSearchResult(sess)
	}), true
}

func (h *keycloakHandler) executeSearchWithFilter(
	req ldap.SearchRequest,
	searchFunc func() (ldap.ServerSearchResult, error),
) searchHandlerResult {
	res, err := searchFunc()
	if err != nil {
		h.log.Error().Err(err).Msg("search response")
		return searchHandlerResult{errorSearchResult(), err}
	}
	filtered, err := filterEntriesForRequest(req, res.Entries)
	if err != nil {
		h.log.Error().Err(err).Msg("search response")
		return searchHandlerResult{errorSearchResult(), err}
	}
	res = successSearchResult(filtered)
	h.logSearchResponse(req.BaseDN, len(res.Entries))
	return searchHandlerResult{res, nil}
}

func (h *keycloakHandler) logSearchRequest(boundDN string, req ldap.SearchRequest) {
	scope := ldap.ScopeMap[req.Scope]
	deferAliases := ldap.DerefMap[req.DerefAliases]
	attributes := strings.Join(req.Attributes, " ")
	controls := h.formatControls(req.Controls)
	h.log.Info().
		Str("boundDN", boundDN).
		Str("baseDN", req.BaseDN).
		Str("scope", scope).
		Str("derefAliases", deferAliases).
		Int("sizeLimit", req.SizeLimit).
		Int("timeLimit", req.TimeLimit).
		Bool("typesOnly", req.TypesOnly).
		Str("filter", req.Filter).
		Str("attributes", attributes).
		Str("controls", controls).
		Msg("search request")
}

func (h *keycloakHandler) logSearchResponse(baseDN string, entries int) {
	h.log.Debug().
		Str("baseDN", baseDN).
		Int("entries", entries).
		Msg("search response")
}

func (h *keycloakHandler) formatControls(controls []ldap.Control) string {
	controlStrs := make([]string, len(controls))
	for i, cc := range controls {
		if s, ok := ldap.ControlTypeMap[cc.GetControlType()]; ok {
			controlStrs[i] = s
		} else {
			controlStrs[i] = cc.GetControlType()
		}
	}
	return strings.Join(controlStrs, " ")
}

func filterEntriesForRequest(req ldap.SearchRequest, entries []*ldap.Entry) ([]*ldap.Entry, error) {
	filterPacket, err := ldap.CompileFilter(req.Filter)
	if err != nil {
		return nil, fmt.Errorf("filter compile failed: %w", err)
	}
	baseLower := strings.ToLower(req.BaseDN)
	filtered := make([]*ldap.Entry, 0, len(entries))
	for _, entry := range entries {
		keep, resultCode := ldap.ServerApplyFilter(filterPacket, entry)
		if resultCode != ldap.LDAPResultSuccess {
			return nil, fmt.Errorf("filter evaluation failed: %v", resultCode)
		}
		if !keep {
			continue
		}
		switch req.Scope {
		case ldap.ScopeWholeSubtree:
		case ldap.ScopeBaseObject:
			if strings.ToLower(entry.DN) != baseLower {
				continue
			}
		case ldap.ScopeSingleLevel:
			if !isSingleLevelScopeMatch(entry.DN, req.BaseDN) {
				continue
			}
		default:
			continue
		}
		filtered = append(filtered, entry)
		if req.SizeLimit > 0 && len(filtered) >= req.SizeLimit {
			break
		}
	}
	return filtered, nil
}

func isSingleLevelScopeMatch(entryDN, baseDN string) bool {
	entryParsed, entryErr := ldapv3.ParseDN(entryDN)
	baseParsed, baseErr := ldapv3.ParseDN(baseDN)
	if entryErr != nil || baseErr != nil {
		return false
	}
	if len(entryParsed.RDNs) != len(baseParsed.RDNs)+1 {
		return false
	}
	offset := len(entryParsed.RDNs) - len(baseParsed.RDNs)
	for i := 0; i < len(baseParsed.RDNs); i++ {
		entryRDN := entryParsed.RDNs[i+offset].String()
		baseRDN := baseParsed.RDNs[i].String()
		if !strings.EqualFold(entryRDN, baseRDN) {
			return false
		}
	}
	return true
}

func (h *keycloakHandler) Search(
	boundDN string,
	req ldap.SearchRequest,
	conn net.Conn,
) (ldap.ServerSearchResult, error) {
	if conn == nil && !allowNilConnectionForTests {
		err := errors.New("nil connection not allowed")
		h.log.Error().Err(err).Msg("search response")
		return errorSearchResult(), err
	}
	h.logSearchRequest(boundDN, req)

	sess, err := h.requireSession(conn, boundDN, true)
	if err != nil {
		h.log.Error().Err(err).Msg("search response")
		return errorSearchResult(), err
	}
	if sess.isUserBound {
		return h.userBoundSearchResult(sess, boundDN, req)
	}
	if err := validateSearchRequestConstraints(req); err != nil {
		h.log.Error().Err(err).Msg("search response")
		return errorSearchResult(), err
	}

	if req.BaseDN == "" && req.Scope == ldap.ScopeBaseObject {
		res := h.rootDSESearchResult()
		h.logSearchResponse(req.BaseDN, len(res.Entries))
		return res, nil
	}

	if res, handled := h.tryMemberOfRolesSearch(sess, req); handled {
		return res.result, res.err
	}

	if res, handled := h.tryMemberOfGroupsSearch(sess, req); handled {
		return res.result, res.err
	}

	if res, handled := h.tryUsersSearch(sess, req); handled {
		return res.result, res.err
	}

	if res, handled := h.tryGroupsSearch(sess, req); handled {
		return res.result, res.err
	}

	scope := ldap.ScopeMap[req.Scope]
	attributes := strings.Join(req.Attributes, " ")
	controls := h.formatControls(req.Controls)
	err = unexpected(fmt.Sprintf("baseDN: \"%s\", scope: \"%s\", filter: \"%s\", attributes: \"%s\", controls: \"%s\"",
		req.BaseDN, scope, req.Filter, attributes, controls))
	h.log.Error().Err(err).Msg("search response")
	return errorSearchResult(), err
}

func errorSearchResult() ldap.ServerSearchResult {
	return ldap.ServerSearchResult{
		Entries:    make([]*ldap.Entry, 0),
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: ldap.LDAPResultOperationsError,
	}
}

func successSearchResult(entries []*ldap.Entry) ldap.ServerSearchResult {
	return ldap.ServerSearchResult{
		Entries:    entries,
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess,
	}
}

func emptySearchResult() ldap.ServerSearchResult {
	return successSearchResult([]*ldap.Entry{})
}

func (h *keycloakHandler) rootDSESearchResult() ldap.ServerSearchResult {
	attributes := buildAttributesFromNames(rootDSEAttributes, "")
	entry := &ldap.Entry{DN: "", Attributes: attributes}
	return successSearchResult([]*ldap.Entry{entry})
}

func userToLDAPEntry(user User, baseDNUsers, ldapDomain string) *ldap.Entry {
	userPrincipalName := fmt.Sprintf("%s@%s", user.Username, ldapDomain)
	objectSidBytes := sid(user.ID, ldapDomain)
	pictureURL := extractPictureURL(user.Attributes)
	attributes := buildUserAttributes(
		user.Username,
		userPrincipalName,
		user.Username,
		user.FirstName,
		user.LastName,
		user.Email,
		pictureURL,
		objectSidBytes,
	)
	dn := fmt.Sprintf("cn=%s,%s", escapeRDNValue(user.Username), baseDNUsers)
	return &ldap.Entry{DN: dn, Attributes: attributes}
}

func groupToLDAPEntry(group Group, baseDNGroups, ldapDomain string) *ldap.Entry {
	objectSidBytes := sid(group.Name, ldapDomain)
	attributes := buildGroupAttributes(group.Name, objectSidBytes)
	dn := fmt.Sprintf("cn=%s,%s", escapeRDNValue(group.Name), baseDNGroups)
	return &ldap.Entry{DN: dn, Attributes: attributes}
}

func extractPictureURL(attributes map[string][]string) string {
	if attributes == nil {
		return ""
	}
	if pictureValues, ok := attributes["picture"]; ok && len(pictureValues) > 0 {
		return pictureValues[0]
	}
	return ""
}

func buildUserAttributes(samAccountName, userPrincipalName, commonName, givenName, familyName, email, jpegPhoto string, objectSidBytes []byte) []*ldap.EntryAttribute {
	displayName := strings.TrimSpace(givenName + " " + familyName)
	if displayName == "" {
		displayName = commonName
	}
	attributes := []attributePair{
		{name: "objectClass", value: "user"},
		{name: "uid", value: samAccountName},
		{name: "userPrincipalName", value: userPrincipalName},
		{name: "cn", value: commonName},
		{name: "givenName", value: givenName},
		{name: "sn", value: familyName},
		{name: "displayName", value: displayName},
		{name: "mail", value: email},
		{name: "description", value: ""},
		{name: "userAccountControl", value: userAccountControlNormal},
		{name: "lockoutTime", value: "0"},
		{name: "objectSid", value: string(objectSidBytes)},
	}
	if jpegPhoto != "" {
		attributes = append(attributes, attributePair{name: "jpegPhoto", value: jpegPhoto})
	}
	return buildAttributesFromPairs(attributes)
}

func buildGroupAttributes(name string, objectSidBytes []byte) []*ldap.EntryAttribute {
	return buildAttributesFromPairs([]attributePair{
		{name: "objectClass", value: "group"},
		{name: "sAMAccountName", value: name},
		{name: "cn", value: name},
		{name: "description", value: name},
		{name: "objectSid", value: string(objectSidBytes)},
	})
}

type attributePair struct {
	name  string
	value string
}

func buildAttributesFromPairs(pairs []attributePair) []*ldap.EntryAttribute {
	attributes := make([]*ldap.EntryAttribute, len(pairs))
	for i, pair := range pairs {
		attributes[i] = newAttribute(pair.name, pair.value)
	}
	return attributes
}

func buildAttributesFromNames(names []string, value string) []*ldap.EntryAttribute {
	attributes := make([]*ldap.EntryAttribute, len(names))
	for i, name := range names {
		attributes[i] = newAttribute(name, value)
	}
	return attributes
}

func buildMemberOfValues(names []string, baseDN string) []string {
	if len(names) == 0 {
		return nil
	}
	values := make([]string, 0, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		values = append(values, fmt.Sprintf("cn=%s,%s", escapeRDNValue(name), baseDN))
	}
	return values
}

func memberOfValuesFromSet(names map[string]bool, baseDN string) []string {
	if len(names) == 0 {
		return nil
	}
	values := make([]string, 0, len(names))
	for name := range names {
		if name == "" {
			continue
		}
		values = append(values, fmt.Sprintf("cn=%s,%s", escapeRDNValue(name), baseDN))
	}
	return values
}

func appendMemberOfAttribute(attributes []*ldap.EntryAttribute, values []string) []*ldap.EntryAttribute {
	if len(values) == 0 {
		return attributes
	}
	return append(attributes, &ldap.EntryAttribute{Name: "memberOf", Values: values})
}

func (h *keycloakHandler) groupsSearchResult(s *session) (ldap.ServerSearchResult, error) {
	groups := &[]Group{}
	err := h.keycloakGet(s, h.keycloakGroupsPath(), groups)
	if err != nil {
		return errorSearchResult(), err
	}
	entries := make([]*ldap.Entry, 0, len(*groups))
	for _, group := range *groups {
		h.log.Debug().
			Str("name", group.Name).
			Str("objectSid", sidToString(sid(group.Name, h.config.ldapDomain))).
			Msg("group")
		entries = append(entries, groupToLDAPEntry(group, h.baseDNGroups, h.config.ldapDomain))
	}
	return successSearchResult(entries), nil
}

func (h *keycloakHandler) usersSearchResult(s *session) (ldap.ServerSearchResult, error) {
	users := &[]User{}
	err := h.keycloakGet(s, h.keycloakUsersPath(), users)
	if err != nil {
		return errorSearchResult(), err
	}
	entries := make([]*ldap.Entry, 0, len(*users))
	for _, user := range *users {
		h.log.Debug().Str("username", user.Username).Msg("user")
		entries = append(entries, userToLDAPEntry(user, h.baseDNUsers, h.config.ldapDomain))
	}
	return successSearchResult(entries), nil
}

// memberOfRolesSearchRoleNames returns role names if the search request is a memberOf filter for ou=roles (e.g. (|(memberOf=cn=role1,ou=roles,...)(memberOf=cn=role2,ou=roles,...))).
// Keycloak's API for users by role is GET /admin/realms/{realm}/roles/{role-name}/users, which expects the role name, not the role ID.
func memberOfRolesSearchRoleNames(req ldap.SearchRequest) []string {
	names := extractMemberOfRoleNames(req.Filter)
	if len(names) == 0 {
		return nil
	}
	return names
}

// usersByMemberOfRolesSearchResult fetches users that have any of the given realm roles (including inherited/composite roles).
// It fetches all users and checks their effective role-mappings (GET /admin/realms/{realm}/users/{userId}/role-mappings/realm/composite)
// to include users who inherit the role through composite roles or groups.
func (h *keycloakHandler) usersByMemberOfRolesSearchResult(s *session, roleNames []string) (ldap.ServerSearchResult, error) {
	if len(roleNames) == 0 {
		return successSearchResult([]*ldap.Entry{}), nil
	}
	targetRoles := make(map[string]bool)
	for _, name := range roleNames {
		if name != "" {
			targetRoles[strings.ToLower(name)] = true
		}
	}
	allUsers := &[]User{}
	if err := h.keycloakGet(s, h.keycloakUsersPath(), allUsers); err != nil {
		h.log.Error().Err(err).Msg("keycloak get all users failed")
		return errorSearchResult(), err
	}
	entriesByID := make(map[string]*ldap.Entry)
	memberOfByID := make(map[string]map[string]bool)
	rolesBaseDN := "ou=roles," + strings.TrimPrefix(h.baseDNUsers, "cn=users,")
	for _, user := range *allUsers {
		effectiveRoles := &[]Role{}
		path := h.keycloakUserRoleMappingsCompositePath(user.ID)
		if err := h.keycloakGet(s, path, effectiveRoles); err != nil {
			h.log.Debug().Err(err).Str("userID", user.ID).Msg("keycloak get user effective roles failed")
			continue
		}
		matchedRoles := make(map[string]bool)
		for _, role := range *effectiveRoles {
			roleLower := strings.ToLower(role.Name)
			if targetRoles[roleLower] {
				matchedRoles[role.Name] = true
			}
		}
		if len(matchedRoles) > 0 {
			entry := userToLDAPEntry(user, h.baseDNUsers, h.config.ldapDomain)
			entriesByID[user.ID] = entry
			memberOfByID[user.ID] = matchedRoles
		}
	}
	entries := make([]*ldap.Entry, 0, len(entriesByID))
	for userID, entry := range entriesByID {
		if rolesForUser := memberOfByID[userID]; len(rolesForUser) > 0 {
			memberOfValues := memberOfValuesFromSet(rolesForUser, rolesBaseDN)
			entry.Attributes = appendMemberOfAttribute(entry.Attributes, memberOfValues)
		}
		entries = append(entries, entry)
	}
	return successSearchResult(entries), nil
}

// usersByMemberOfGroupsSearchResult fetches users that belong to any of the given Keycloak groups by calling
// GET /admin/realms/{realm}/groups (to resolve name -> id) and GET /admin/realms/{realm}/groups/{id}/members.
func (h *keycloakHandler) usersByMemberOfGroupsSearchResult(s *session, groupNames []string) (ldap.ServerSearchResult, error) {
	allGroups := &[]Group{}
	if err := h.keycloakGet(s, h.keycloakGroupsPath(), allGroups); err != nil {
		h.log.Error().Err(err).Msg("keycloak get groups failed")
		return errorSearchResult(), err
	}
	nameToID := make(map[string]string)
	for _, g := range *allGroups {
		if g.Name != "" {
			nameToID[strings.ToLower(g.Name)] = g.ID
		}
	}
	entriesByID := make(map[string]*ldap.Entry)
	memberOfByID := make(map[string]map[string]bool)
	for _, groupName := range groupNames {
		if groupName == "" {
			continue
		}
		groupID, ok := nameToID[strings.ToLower(groupName)]
		if !ok {
			h.log.Debug().Str("groupName", groupName).Msg("group not found in Keycloak")
			continue
		}
		users := &[]User{}
		path := h.keycloakGroupMembersPath(groupID)
		if err := h.keycloakGet(s, path, users); err != nil {
			h.log.Debug().Err(err).Str("groupName", groupName).Str("groupID", groupID).Msg("keycloak get group members failed")
			continue
		}
		for _, user := range *users {
			entry, ok := entriesByID[user.ID]
			if !ok {
				entry = userToLDAPEntry(user, h.baseDNUsers, h.config.ldapDomain)
				entriesByID[user.ID] = entry
			}
			if memberOfByID[user.ID] == nil {
				memberOfByID[user.ID] = make(map[string]bool)
			}
			memberOfByID[user.ID][groupName] = true
		}
	}
	entries := make([]*ldap.Entry, 0, len(entriesByID))
	for userID, entry := range entriesByID {
		if groupsForUser := memberOfByID[userID]; len(groupsForUser) > 0 {
			memberOfValues := memberOfValuesFromSet(groupsForUser, h.baseDNGroups)
			entry.Attributes = appendMemberOfAttribute(entry.Attributes, memberOfValues)
		}
		entries = append(entries, entry)
	}
	return successSearchResult(entries), nil
}

func buildUserBoundEntry(h *keycloakHandler, info *userinfoResponse, boundDN string) *ldap.Entry {
	userDN := fmt.Sprintf("cn=%s,%s", escapeRDNValue(info.PreferredName), h.baseDNUsers)
	entryDN := userDN
	if boundDN != "" {
		entryDN = boundDN
	}
	userPrincipalName := fmt.Sprintf("%s@%s", info.PreferredName, h.config.ldapDomain)
	samAccountName := info.PreferredName
	commonName := info.PreferredName
	if boundCN, ok := parseCommonNameFromDN(boundDN); ok {
		samAccountName = boundCN
		commonName = boundCN
	}
	objectSidBytes := sid(info.Sub, h.config.ldapDomain)
	attributes := buildUserAttributes(
		samAccountName,
		userPrincipalName,
		commonName,
		info.GivenName,
		info.FamilyName,
		info.Email,
		info.Picture,
		objectSidBytes,
	)
	rolesBaseDN := "ou=roles," + strings.TrimPrefix(h.baseDNUsers, "cn=users,")
	groupNames := make([]string, 0)
	for _, g := range info.Groups {
		cn := groupPathToCN(g)
		if cn != "" {
			groupNames = append(groupNames, cn)
		}
	}
	memberOfValues := append(
		buildMemberOfValues(groupNames, h.baseDNGroups),
		buildMemberOfValues(realmRolesFromUserinfo(info), rolesBaseDN)...,
	)
	attributes = appendMemberOfAttribute(attributes, memberOfValues)
	return &ldap.Entry{DN: entryDN, Attributes: attributes}
}

func (h *keycloakHandler) userBoundSearchResult(s *session, boundDN string, req ldap.SearchRequest) (ldap.ServerSearchResult, error) {
	info, err := h.keycloakUserinfo(s)
	if err != nil {
		h.log.Error().Err(err).Msg("userinfo failed")
		return errorSearchResult(), err
	}
	userDN := fmt.Sprintf("cn=%s,%s", escapeRDNValue(info.PreferredName), h.baseDNUsers)
	entry := buildUserBoundEntry(h, info, boundDN)

	if !strings.EqualFold(req.BaseDN, h.baseDNUsers) && !strings.EqualFold(req.BaseDN, userDN) && !strings.EqualFold(req.BaseDN, boundDN) {
		return emptySearchResult(), nil
	}
	if req.Scope != ldap.ScopeBaseObject && req.Scope != ldap.ScopeSingleLevel && req.Scope != ldap.ScopeWholeSubtree {
		return emptySearchResult(), nil
	}
	if req.Scope == ldap.ScopeBaseObject && !strings.EqualFold(req.BaseDN, userDN) && !strings.EqualFold(req.BaseDN, boundDN) {
		return emptySearchResult(), nil
	}
	filtered, err := filterEntriesForRequest(req, []*ldap.Entry{entry})
	if err != nil {
		h.log.Error().Err(err).Msg("search response")
		return errorSearchResult(), err
	}
	if len(filtered) == 0 {
		return emptySearchResult(), nil
	}
	return successSearchResult(filtered), nil
}
