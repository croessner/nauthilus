package core

import (
	"fmt"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

// PluginPasswordCacheBackend restores cache data through the original plugin result adapter.
type PluginPasswordCacheBackend interface {
	PositivePasswordCacheEnabled() bool
	RestorePositivePasswordCache(*AuthState, string) (*PassDBResult, error)
}

// capturePluginPositiveCache freezes backend evidence independently of later subject mutations.
func (a *AuthState) capturePluginPositiveCache(result *PassDBResult) {
	a.pluginPositiveCache = nil

	if result.Backend != definitions.BackendPlugin || !result.Authenticated || !result.UserFound || result.PluginCachePayload == "" {
		return
	}

	a.pluginPositiveCache = &bktype.PositivePasswordCache{
		Backend:      definitions.BackendPlugin,
		BackendName:  result.BackendName,
		PluginResult: result.PluginCachePayload,
	}
}

// pluginCacheNameEnabled checks current instance admission before touching a plugin cache.
func (a *AuthState) pluginCacheNameEnabled(cacheName string) bool {
	plan := a.buildBackendExecutionPlan()
	for name := range plan.pluginCacheBackends {
		if backend.PluginPasswordCacheName(name) == cacheName {
			return true
		}
	}

	return false
}

// restorePluginPositiveCache rejects foreign, disabled, or stale-contract plugin entries.
func (a *AuthState) restorePluginPositiveCache(cacheName string, cached *bktype.PositivePasswordCache) (*PassDBResult, bool, error) {
	if !a.pluginCacheNameEnabled(cacheName) || cacheName != backend.PluginPasswordCacheName(cached.BackendName) {
		return nil, false, nil
	}

	manager, ok := a.GetBackendManager(definitions.BackendPlugin, cached.BackendName).(PluginPasswordCacheBackend)
	if !ok || !manager.PositivePasswordCacheEnabled() {
		return nil, false, nil
	}

	result, err := manager.RestorePositivePasswordCache(a, cached.PluginResult)

	return result, result != nil, err
}

// buildTypedPluginBackendExecutionPlan admits only plugin backends and their explicit positive cache.
// Cache namespaces from other backend families never enter this typed provider's authority.
func (a *AuthState) buildTypedPluginBackendExecutionPlan() (backendExecutionPlan, error) {
	plan := backendExecutionPlan{positions: make(map[definitions.Backend]int)}

	for index, entry := range a.Cfg().GetServer().GetBackends() {
		if entry == nil || (entry.Get() != definitions.BackendPlugin && entry.Get() != definitions.BackendCache) {
			continue
		}

		before := len(plan.passDBs)
		a.appendConfiguredBackend(&plan, entry)
		plan.recordPosition(entry.Get(), index, len(plan.passDBs) > before)
	}

	plan.scopePluginPasswordCache()

	if _, found := plan.positions[definitions.BackendPlugin]; !found {
		return backendExecutionPlan{}, fmt.Errorf("typed plugin backend provider has no executable backend")
	}

	return plan, nil
}

// scopePluginPasswordCache removes unused caches or binds each cache callback to admitted plugin namespaces.
func (p *backendExecutionPlan) scopePluginPasswordCache() {
	names := make([]string, 0, len(p.pluginCacheBackends))
	for _, entry := range p.passDBs {
		if entry.backend == definitions.BackendPlugin && p.pluginCacheBackends[entry.name] {
			names = append(names, backend.PluginPasswordCacheName(entry.name))
		}
	}

	selected := p.passDBs[:0]
	for _, entry := range p.passDBs {
		if entry.backend == definitions.BackendCache {
			if len(names) == 0 {
				continue
			}

			entry.fn = func(auth *AuthState) (*PassDBResult, error) { return cachePassDB(auth, names) }
		}

		selected = append(selected, entry)
	}

	p.passDBs = selected
	if len(names) == 0 {
		p.hasPositivePasswordCache = false
		delete(p.positions, definitions.BackendCache)
	}
}

// PluginPasswordCacheScopeBackend validates additional plugin identity inputs for local hits.
type PluginPasswordCacheScopeBackend interface {
	PasswordCacheScopeMatches(*AuthState, string) bool
}

// pluginLocalCacheScopeMatches guards plugin evidence before any request state is restored.
func (a *AuthState) pluginLocalCacheScopeMatches(snapshot *CachedBackendAuthentication) bool {
	if snapshot.sourceBackend != definitions.BackendPlugin {
		return true
	}

	manager := a.GetBackendManager(definitions.BackendPlugin, snapshot.backendName)
	scoped, ok := manager.(PluginPasswordCacheScopeBackend)

	return ok && scoped.PasswordCacheScopeMatches(a, snapshot.pluginCachePayload)
}
