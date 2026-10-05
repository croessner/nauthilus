package core

import (
	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

// scopeTypedPasswordCache preserves cache order while confining evidence to the selected family and instances.
func (p *backendExecutionPlan) scopeTypedPasswordCache(family definitions.Backend) {
	instances := make(map[string]bool)

	for _, entry := range p.passDBs {
		if entry.backend == family {
			instances[entry.name] = true
		}
	}

	cacheFamily := definitions.CacheLDAP
	if family == definitions.BackendLua {
		cacheFamily = definitions.CacheLua
	}

	for _, entry := range p.passDBs {
		if entry.backend != definitions.BackendCache {
			continue
		}

		entry.fn = func(auth *AuthState) (*PassDBResult, error) {
			names := backend.GetCacheNames(auth.Cfg(), auth.Channel(), auth.Request.Protocol.Get(), cacheFamily)

			return cachePassDBMatching(auth, names.GetStringSlice(), func(cached *bktype.PositivePasswordCache) bool {
				return cached.Backend == family && instances[cached.BackendName]
			})
		}
	}
}

// acceptsCachedBackend admits only backend instances executable by this request's selected plan.
func (p backendExecutionPlan) acceptsCachedBackend(family definitions.Backend, name string) bool {
	for _, entry := range p.passDBs {
		if entry.backend == family && entry.name == name {
			return true
		}
	}

	return false
}
