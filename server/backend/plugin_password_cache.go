package backend

import (
	"strings"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

// pluginPasswordCacheNamespace cannot collide with printable operator-owned LDAP/Lua cache names.
const pluginPasswordCacheNamespace = "\x00plugin."

// PluginPasswordCacheName isolates native backend instances with a reserved internal NUL separator.
func PluginPasswordCacheName(name string) string { return pluginPasswordCacheNamespace + name }

// IsPluginPasswordCacheName identifies only the reserved internal namespace, never a printable cache_name.
func IsPluginPasswordCacheName(name string) bool {
	return strings.HasPrefix(name, pluginPasswordCacheNamespace)
}

// PositiveCacheProtocols includes plugin-only configurations in account lookup and purge walks.
// Plugin keys are protocol-independent; their payload separately binds the request scope.
func PositiveCacheProtocols(cfg config.File) []string {
	protocols := cfg.GetAllProtocols()
	for _, entry := range cfg.GetServer().GetBackends() {
		if entry != nil && entry.Get() == definitions.BackendPlugin {
			return append(protocols, "")
		}
	}

	return protocols
}

// PositivePasswordCacheKey builds the shared Redis namespace used by writes, reads and invalidation.
func PositivePasswordCacheKey(prefix, cacheName, account string) string {
	return prefix + definitions.RedisUserPositiveCachePrefix + cacheName + ":" + account
}
