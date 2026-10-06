package backend

import (
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

// PositiveCacheKeys is the shared inventory for password and identity cache invalidation.
// The identity epoch additionally invalidates aliases that cannot yet be resolved to an account.
func PositiveCacheKeys(cfg config.File, channel Channel, prefix string, protocols, accounts []string) config.StringSet {
	keys := config.NewStringSet()

	for _, protocol := range protocols {
		names := GetCacheNames(cfg, channel, protocol, definitions.CacheAll)
		for _, name := range names.GetStringSlice() {
			for _, account := range accounts {
				keys.Set(PositivePasswordCacheKey(prefix, name, account))
			}
		}
	}

	if ldap := cfg.GetLDAP(); ldap != nil {
		for _, search := range ldap.Search {
			for _, account := range accounts {
				keys.Set(IdentityCacheKey(prefix, search.CacheName, account))
			}
		}
	}

	return keys
}
