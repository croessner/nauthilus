package core

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/util"
	jsoniter "github.com/json-iterator/go"
)

// positiveIdentityCache is a backend attribute snapshot without credential or authorization evidence.
type positiveIdentityCache struct {
	Attributes              bktype.AttributeMapping `json:"attributes"`
	Groups                  []string                `json:"groups"`
	GroupDistinguishedNames []string                `json:"group_dns"`
}

// ldapIdentityCacheLookup owns the immutable scope and pre-lookup invalidation fence.
type ldapIdentityCacheLookup struct {
	cache    *backend.IdentityCache
	protocol *config.LDAPSearchProtocol
	key      string
	scope    string
	epoch    string
}

// PassDB caches only trusted identity lookups; password and master-user operations always reach LDAP.
func (lm *ldapManagerImpl) PassDB(auth *AuthState) (*PassDBResult, error) {
	lookup := lm.newIdentityCacheLookup(auth)
	if lookup == nil {
		return lm.passDB(auth)
	}

	if result := lookup.load(auth, lm.poolName); result != nil {
		return result, nil
	}

	result, err := lm.passDB(auth)
	if err == nil && result != nil && result.UserFound {
		lookup.store(auth, result)
	}

	return result, err
}

// identityCacheEligible excludes credential verification and mutable browser MFA state.
func identityCacheEligible(auth *AuthState) bool {
	if !auth.Request.NoAuth || auth.Runtime.MasterUserMode || auth.masterUserIdentity().active {
		return false
	}

	if auth.Request.Protocol == nil || auth.Redis() == nil || auth.Request.Service == definitions.ServIDP || auth.Runtime.IDPContext != nil {
		return false
	}

	return auth.Cfg().GetServer().GetRedis().GetIdentityCacheEnabled()
}

// newIdentityCacheLookup resolves an exact LDAP lookup scope before any backend work.
func (lm *ldapManagerImpl) newIdentityCacheLookup(auth *AuthState) *ldapIdentityCacheLookup {
	if !identityCacheEligible(auth) {
		return nil
	}

	protocol, err := lm.effectiveCfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName)
	if err != nil || protocol == nil {
		return nil
	}

	cacheName, err := protocol.GetCacheName()
	if err != nil {
		return nil
	}

	scope, err := lm.identityCacheScope(auth, protocol)
	if err != nil {
		return nil
	}

	cache := backend.NewIdentityCache(auth.Cfg(), auth.Redis())

	epoch, err := cache.Generation(auth.Ctx())
	if err != nil || epoch == "" {
		return nil
	}

	return &ldapIdentityCacheLookup{cache: cache, protocol: protocol,
		key: backend.IdentityCacheKey(auth.Cfg().GetServer().GetRedis().GetPrefix(), cacheName, auth.Request.Username), scope: scope, epoch: epoch}
}

// identityCacheScope hashes the effective LDAP filters/configuration and explicit client identity.
// Rendering only configured macros avoids tying entries to unused ephemeral client ports.
func (lm *ldapManagerImpl) identityCacheScope(auth *AuthState, protocol *config.LDAPSearchProtocol) (string, error) {
	data, err := jsoniter.ConfigFastest.MarshalToString(struct {
		Protocol *config.LDAPSearchProtocol
		Pool     *config.LDAPConf
	}{protocol, lm.getPoolLDAPConf()})
	if err != nil {
		return "", err
	}

	scope := []string{lm.poolName, auth.Request.Protocol.Get(), auth.Request.OIDCCID, auth.Request.SAMLEntityID,
		util.ExpandLDAPFilter(data, lm.newMacroSource(auth, true))}

	encoded, err := jsoniter.ConfigFastest.Marshal(scope)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(encoded)

	return hex.EncodeToString(digest[:]), nil
}

// load restores only LDAP identity fields and leaves all downstream policy processing active.
func (l *ldapIdentityCacheLookup) load(auth *AuthState, pool string) *PassDBResult {
	data, err := l.cache.Load(auth.Ctx(), l.key, l.scope)
	if err != nil || len(data) == 0 {
		return nil
	}

	var snapshot positiveIdentityCache
	if err = jsoniter.ConfigFastest.Unmarshal(data, &snapshot); err != nil {
		return nil
	}

	if len(snapshot.Attributes[definitions.DistinguishedName]) == 0 {
		return nil
	}

	accountField, err := l.protocol.GetAccountField()
	if err != nil {
		return nil
	}

	result := GetPassDBResultFromPool()
	result.UserFound = true
	result.Authenticated = true // NoAuth lookup evidence only; this cache is unreachable from Authenticate.
	result.IdentityCacheHit = true
	result.Backend = definitions.BackendLDAP
	result.BackendName = pool
	result.Attributes = snapshot.Attributes
	result.Groups = snapshot.Groups
	result.GroupDistinguishedNames = snapshot.GroupDistinguishedNames

	if _, ok := snapshot.Attributes[accountField]; ok {
		result.AccountField = accountField
	}

	applyLDAPPassDBProtocolFields(result, l.protocol, accountField)

	return result
}

// store captures the raw backend result before subjects, actions, or policy can mutate attributes.
func (l *ldapIdentityCacheLookup) store(auth *AuthState, result *PassDBResult) {
	data, err := jsoniter.ConfigFastest.Marshal(positiveIdentityCache{Attributes: result.Attributes, Groups: result.Groups, GroupDistinguishedNames: result.GroupDistinguishedNames})
	if err == nil {
		err = l.cache.Store(auth.Ctx(), l.key, l.epoch, l.scope, data, auth.Cfg().GetServer().GetRedis().GetIdentityCacheTTL())
	}

	if err != nil {
		level.Warn(auth.Logger()).Log(definitions.LogKeyMsg, "Could not store identity cache", definitions.LogKeyError, err)
	}
}
