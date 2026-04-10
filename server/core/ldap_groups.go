// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package core

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/localcache"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/go-ldap/ldap/v3"
)

// ldapMembershipCache is a sharded memory cache for LDAP group resolutions.
var ldapMembershipCache = localcache.NewMemoryShardedCache(32, 2*time.Minute, 10*time.Minute)

// cachedGroupResolution stores resolved groups and their DNs in the cache.
type cachedGroupResolution struct {
	Groups   []string
	GroupDNs []string
}

// groupSearchBaseDN determines the base DN for group searches.
func (lm *ldapManagerImpl) groupSearchBaseDN(protocol *config.LDAPSearchProtocol, groupsCfg *config.LDAPGroups) string {
	if groupsCfg != nil && groupsCfg.GetBaseDN() != "" {
		return groupsCfg.GetBaseDN()
	}

	if protocol == nil {
		return ""
	}

	baseDN, err := protocol.GetBaseDN()
	if err != nil {
		return ""
	}

	return baseDN
}

// groupSearchFilter determines the LDAP filter for group searches.
func (lm *ldapManagerImpl) groupSearchFilter(groupsCfg *config.LDAPGroups) string {
	if groupsCfg != nil && strings.TrimSpace(groupsCfg.GetFilter()) != "" {
		return groupsCfg.GetFilter()
	}

	return "(|(member=%{user_dn})(uniqueMember=%{user_dn})(memberUid=%{account}))"
}

// getPoolLDAPConf retrieves the LDAP configuration for the current pool.
func (lm *ldapManagerImpl) getPoolLDAPConf() *config.LDAPConf {
	cfg := lm.effectiveCfg()
	if cfg == nil || cfg.GetLDAP() == nil {
		return nil
	}

	if lm.poolName == definitions.DefaultBackendName {
		poolCfg := cfg.GetLDAP().GetConfig()
		if typed, ok := poolCfg.(*config.LDAPConf); ok {
			return typed
		}

		return nil
	}

	pools := cfg.GetLDAP().GetOptionalLDAPPools()
	if pools == nil {
		return nil
	}

	return pools[lm.poolName]
}

// groupResolutionCacheKey generates a unique cache key for group resolution.
func groupResolutionCacheKey(poolName string, protocolName string, strategy string, membershipAttribute string, groupBaseDN string, groupFilter string, username string, userDN string, account string) string {
	return strings.Join([]string{
		"ldap-groups",
		poolName,
		protocolName,
		strategy,
		membershipAttribute,
		groupBaseDN,
		groupFilter,
		username,
		userDN,
		account,
	}, "|")
}

// getSingleStringAttribute retrieves a single string value from an AttributeMapping.
func getSingleStringAttribute(attributes bktype.AttributeMapping, key string) string {
	values, ok := attributes[key]
	if !ok || len(values) == 0 {
		return ""
	}

	switch typed := values[definitions.LDAPSingleValue].(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return ""
	}
}

// extractGroupNameFromDN extracts the common name or organizational unit from a DN.
func extractGroupNameFromDN(groupDN string) string {
	parsed, err := ldap.ParseDN(groupDN)
	if err != nil || parsed == nil {
		return ""
	}

	if len(parsed.RDNs) == 0 {
		return ""
	}

	for _, attr := range parsed.RDNs[0].Attributes {
		if strings.EqualFold(attr.Type, "cn") || strings.EqualFold(attr.Type, "ou") {
			return strings.TrimSpace(attr.Value)
		}
	}

	for _, attr := range parsed.RDNs[0].Attributes {
		if strings.TrimSpace(attr.Value) != "" {
			return strings.TrimSpace(attr.Value)
		}
	}

	return ""
}

// isLikelyDN checks if a string looks like an LDAP Distinguished Name.
func isLikelyDN(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}

	return strings.Contains(trimmed, "=") && strings.Contains(trimmed, ",")
}

// resolveMemberOfGroups resolves groups from the memberOf-style attribute.
func (lm *ldapManagerImpl) resolveMemberOfGroups(groupsCfg *config.LDAPGroups, attributes bktype.AttributeMapping) (groups []string, groupDNs []string) {
	if groupsCfg == nil || !groupsCfg.UsesMemberOf() {
		return nil, nil
	}

	membershipAttribute := groupsCfg.GetAttribute()
	values, ok := attributes[membershipAttribute]
	if !ok || len(values) == 0 {
		return nil, nil
	}

	groups = make([]string, 0, len(values))
	groupDNs = make([]string, 0, len(values))

	for _, value := range values {
		var membership string

		switch typed := value.(type) {
		case string:
			membership = typed
		case []byte:
			membership = string(typed)
		default:
			continue
		}

		membership = strings.TrimSpace(membership)
		if membership == "" {
			continue
		}

		if isLikelyDN(membership) {
			groupDNs = append(groupDNs, membership)

			groupName := extractGroupNameFromDN(membership)
			if groupName != "" {
				groups = append(groups, groupName)
			} else {
				groups = append(groups, membership)
			}

			continue
		}

		groups = append(groups, membership)
	}

	return normalizeStringSet(groups), normalizeStringSet(groupDNs)
}

// runGroupSearch executes an LDAP search for groups.
func (lm *ldapManagerImpl) runGroupSearch(ctx context.Context, auth *AuthState, protocol *config.LDAPSearchProtocol, groupsCfg *config.LDAPGroups, account string, memberDN string) (*bktype.LDAPReply, error) {
	baseDN := lm.groupSearchBaseDN(protocol, groupsCfg)
	if baseDN == "" {
		return nil, fmt.Errorf("group search base DN is empty")
	}

	groupFilter := lm.groupSearchFilter(groupsCfg)
	nameAttribute := groupsCfg.GetNameAttribute()
	searchAttributes := []string{nameAttribute}

	if nameAttribute == "" {
		searchAttributes = []string{}
	}

	macroSource := lm.newMacroSource(auth, false)
	macroSource.Account = account
	macroSource.UserDN = memberDN

	replyChan := make(chan *bktype.LDAPReply, 1)

	priority := lm.requestPriority(auth)

	groupScope := groupsCfg.GetScope()
	request := &bktype.LDAPRequest{
		GUID:              auth.Runtime.GUID,
		Command:           definitions.LDAPSearch,
		PoolName:          lm.poolName,
		Filter:            groupFilter,
		BaseDN:            baseDN,
		SearchAttributes:  searchAttributes,
		MacroSource:       macroSource,
		Scope:             *groupScope,
		LDAPReplyChan:     replyChan,
		HTTPClientContext: ctx,
	}

	lm.ldapQueue().Push(request, priority)

	reply := <-replyChan
	if reply == nil {
		return nil, fmt.Errorf("group search returned nil reply")
	}

	return reply, nil
}

// resolveSearchGroups resolves groups by performing LDAP searches.
func (lm *ldapManagerImpl) resolveSearchGroups(auth *AuthState, protocol *config.LDAPSearchProtocol, groupsCfg *config.LDAPGroups, account string, userDN string) (groups []string, groupDNs []string, err error) {
	if groupsCfg == nil || !groupsCfg.UsesSearch() {
		return nil, nil, nil
	}

	maxDepth := 1
	if groupsCfg.Recursive {
		maxDepth = groupsCfg.GetMaxDepth()
	}

	frontier := []string{userDN}
	if strings.TrimSpace(userDN) == "" {
		frontier = []string{""}
	}

	visitedMembers := make(map[string]struct{}, maxDepth*2)
	groupsAcc := make([]string, 0, 8)
	groupDNAcc := make([]string, 0, 8)
	nameAttribute := groupsCfg.GetNameAttribute()

	for depth := 0; depth < maxDepth; depth++ {
		nextFrontier := make([]string, 0, len(frontier))

		for _, memberDN := range frontier {
			memberKey := memberDN
			if memberKey == "" {
				memberKey = "__EMPTY__"
			}

			if _, seen := visitedMembers[memberKey]; seen {
				continue
			}

			visitedMembers[memberKey] = struct{}{}

			searchCtx, cancel := context.WithTimeout(auth.Ctx(), lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPSearch())
			reply, searchErr := lm.runGroupSearch(searchCtx, auth, protocol, groupsCfg, account, memberDN)
			cancel()
			if searchErr != nil {
				return nil, nil, searchErr
			}

			if reply.Err != nil {
				return nil, nil, reply.Err
			}

			if reply.Result == nil {
				continue
			}

			if values, ok := reply.Result[nameAttribute]; ok {
				groupsAcc = append(groupsAcc, anySliceToStrings(values)...)
			}

			if values, ok := reply.Result[definitions.DistinguishedName]; ok {
				discoveredGroupDNs := anySliceToStrings(values)
				groupDNAcc = append(groupDNAcc, discoveredGroupDNs...)

				if groupsCfg.Recursive {
					nextFrontier = append(nextFrontier, discoveredGroupDNs...)
				}
			}
		}

		if !groupsCfg.Recursive || len(nextFrontier) == 0 {
			break
		}

		frontier = nextFrontier
	}

	return normalizeStringSet(groupsAcc), normalizeStringSet(groupDNAcc), nil
}

// resolveGroups orchestrates the resolution of LDAP groups using configured strategies.
func (lm *ldapManagerImpl) resolveGroups(auth *AuthState, protocol *config.LDAPSearchProtocol, attributes bktype.AttributeMapping, accountField string, logger *slog.Logger) (groups []string, groupDNs []string) {
	if protocol == nil {
		return nil, nil
	}

	groupsCfg := protocol.GetGroups()
	if attributes == nil {
		return nil, nil
	}

	if groupsCfg == nil || !groupsCfg.IsEnabled() {
		legacyGroups, legacyGroupDNs := lm.resolveMemberOfGroups(&config.LDAPGroups{
			Strategy:  "member_of",
			Attribute: "memberOf",
		}, attributes)

		return mergeNormalizedStringSlices(
			getNormalizedAttributeStrings(attributes, "groups"),
			legacyGroups,
		), legacyGroupDNs
	}

	userDN := getSingleStringAttribute(attributes, definitions.DistinguishedName)
	account := getSingleStringAttribute(attributes, accountField)

	groupBaseDN := lm.groupSearchBaseDN(protocol, groupsCfg)
	groupFilter := lm.groupSearchFilter(groupsCfg)
	cacheKey := groupResolutionCacheKey(
		lm.poolName,
		auth.Request.Protocol.Get(),
		groupsCfg.GetStrategy(),
		groupsCfg.GetAttribute(),
		groupBaseDN,
		groupFilter,
		auth.Request.Username,
		userDN,
		account,
	)

	cacheTTL := time.Duration(0)
	if poolCfg := lm.getPoolLDAPConf(); poolCfg != nil {
		cacheTTL = poolCfg.GetMembershipCacheTTL()
	}

	if cacheTTL > 0 {
		if cachedValue, ok := ldapMembershipCache.Get(cacheKey); ok {
			if cached, ok := cachedValue.(cachedGroupResolution); ok {
				return cached.Groups, cached.GroupDNs
			}
		}
	}

	memberOfGroups, memberOfGroupDNs := lm.resolveMemberOfGroups(groupsCfg, attributes)
	searchGroups, searchGroupDNs, err := lm.resolveSearchGroups(auth, protocol, groupsCfg, account, userDN)
	if err != nil {
		if logger != nil {
			level.Warn(logger).Log(
				definitions.LogKeyGUID, auth.Runtime.GUID,
				definitions.LogKeyLDAPPoolName, lm.poolName,
				definitions.LogKeyMsg, "group_resolution_failed",
				definitions.LogKeyError, err,
			)
		}
	}

	resolvedGroups := mergeNormalizedStringSlices(memberOfGroups, searchGroups)
	resolvedGroupDNs := mergeNormalizedStringSlices(memberOfGroupDNs, searchGroupDNs)

	if cacheTTL > 0 {
		ldapMembershipCache.Set(cacheKey, cachedGroupResolution{
			Groups:   resolvedGroups,
			GroupDNs: resolvedGroupDNs,
		}, cacheTTL)
	}

	return resolvedGroups, resolvedGroupDNs
}
