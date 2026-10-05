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
	"crypto/sha256"
	"slices"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/definitions"
	monittrace "github.com/croessner/nauthilus/v4/server/monitoring/trace"
	"github.com/croessner/nauthilus/v4/server/stats"
	"github.com/croessner/nauthilus/v4/server/util"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// fullPasswordHashLength is the lowercase hex length of the full SHA-256 password hash.
const fullPasswordHashLength = 2 * sha256.Size

// CachePassDB implements the redis password database backend.
func CachePassDB(auth *AuthState) (*PassDBResult, error) {
	return cachePassDB(auth, nil)
}

// cachePassDB restricts typed provider lookups to an explicit cache namespace set when supplied.
func cachePassDB(auth *AuthState, cacheNames []string) (passDBResult *PassDBResult, err error) {
	// Root span for cache backend lookup
	tr := monittrace.New("nauthilus/cache_backend")
	ctx, sp := tr.Start(auth.Ctx(), "cache.passdb",
		attribute.String("service", auth.Request.Service),
		attribute.String("username", auth.Request.Username),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	requestScope := auth.scopeRequestContext(ctx, nil)

	defer requestScope.Restore()

	defer sp.End()

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, auth.Request.Service)
	stopTimer := stats.PrometheusTimer(auth.Cfg(), definitions.PromBackend, "cache_backend_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	passDBResult = GetPassDBResultFromPool()

	accountName, err := auth.updateUserAccountInRedis()
	if err != nil {
		sp.RecordError(err)

		return
	}

	if accountName != "" {
		err = auth.loadPositivePasswordCache(tr, accountName, passDBResult, cacheNames)
	}

	return
}

// loadPositivePasswordCache searches configured positive password caches for one account.
func (auth *AuthState) loadPositivePasswordCache(tr monittrace.Tracer, accountName string, passDBResult *PassDBResult, cacheNames []string) error {
	if cacheNames == nil {
		names := backend.GetCacheNames(auth.Cfg(), auth.Channel(), auth.Request.Protocol.Get(), definitions.CacheAll)
		cacheNames = names.GetStringSlice()
	}

	for _, cacheName := range cacheNames {
		if backend.IsPluginPasswordCacheName(cacheName) && !auth.pluginCacheNameEnabled(cacheName) {
			continue
		}
		ppc, found, authenticated, err := auth.readPositivePasswordCache(tr, cacheName, accountName)
		if err != nil {
			return err
		}

		if !found {
			continue
		}

		applied, err := auth.restorePositivePasswordCacheResult(cacheName, ppc, authenticated, passDBResult)
		if err != nil {
			return err
		}

		if !applied {
			continue
		}

		break
	}

	return nil
}

// readPositivePasswordCache loads one positive password cache entry and annotates its span.
func (auth *AuthState) readPositivePasswordCache(tr monittrace.Tracer, cacheName string, accountName string) (*bktype.PositivePasswordCache, bool, bool, error) {
	cctx, csp := tr.Start(auth.Ctx(), "cache.get",
		attribute.String("cache_name", cacheName),
	)

	requestScope := auth.scopeRequestContext(cctx, nil)

	defer requestScope.Restore()

	defer csp.End()

	ppc := &bktype.PositivePasswordCache{}

	isRedisErr, err := backend.LoadCacheFromRedisWithSF(auth.Ctx(), auth.Cfg(), auth.Logger(), auth.deps.Redis, auth.positivePasswordCacheKey(cacheName, accountName), ppc)
	if err != nil {
		csp.RecordError(err)

		return nil, false, false, err
	}

	if isRedisErr {
		csp.SetAttributes(attribute.Bool("hit", false))

		return nil, false, false, nil
	}

	if !auth.Request.NoAuth && !isLowercaseHexHash(ppc.Password) {
		csp.SetAttributes(attribute.Bool("hit", false))

		return nil, false, false, nil
	}

	authenticated := auth.Request.NoAuth || positivePasswordCacheHashMatches(ppc.Password, preparedCredentialDigest(auth))
	applyPositivePasswordCacheSpan(csp, authenticated)

	return ppc, true, authenticated, nil
}

// positivePasswordCacheKey builds the Redis key for a positive password cache entry.
func (auth *AuthState) positivePasswordCacheKey(cacheName string, accountName string) string {
	return backend.PositivePasswordCacheKey(auth.cfg().GetServer().GetRedis().GetPrefix(), cacheName, accountName)
}

// applyPositivePasswordCacheResult copies cached user data into the PassDB result.
func applyPositivePasswordCacheResult(passDBResult *PassDBResult, ppc *bktype.PositivePasswordCache, authenticated bool) {
	passDBResult.UserFound = true
	passDBResult.AccountField = ppc.AccountField
	passDBResult.TOTPSecretField = ppc.TOTPSecretField
	passDBResult.TOTPRecoveryField = ppc.TOTPRecoveryField
	passDBResult.UniqueUserIDField = ppc.UniqueUserIDField
	passDBResult.DisplayNameField = ppc.DisplayNameField
	passDBResult.Backend = ppc.Backend
	passDBResult.BackendName = ppc.BackendName
	passDBResult.Attributes = ppc.Attributes
	passDBResult.Groups = slices.Clone(ppc.Groups)
	passDBResult.GroupDistinguishedNames = slices.Clone(ppc.GroupDistinguishedNames)

	if authenticated {
		passDBResult.Authenticated = true
	}
}

// applyPositivePasswordCacheSpan records the hit state for a positive cache lookup.
func applyPositivePasswordCacheSpan(csp trace.Span, authenticated bool) {
	csp.SetAttributes(
		attribute.Bool("hit", true),
		attribute.Bool("authenticated", authenticated),
	)
}

// positivePasswordCacheHashMatches validates and compares one Redis cache value exactly.
func positivePasswordCacheHashMatches(stored string, passwordHash string) bool {
	return isLowercaseHexHash(stored) && stored == passwordHash
}

// isLowercaseHexHash accepts only the full lowercase SHA-256 Redis hash format.
func isLowercaseHexHash(value string) bool {
	if len(value) != fullPasswordHashLength {
		return false
	}

	for _, char := range value {
		if char < '0' || (char > '9' && char < 'a') || char > 'f' {
			return false
		}
	}

	return true
}

// restorePositivePasswordCacheResult enforces namespace ownership before restoring a backend result.
func (auth *AuthState) restorePositivePasswordCacheResult(cacheName string, cached *bktype.PositivePasswordCache, authenticated bool, target *PassDBResult) (bool, error) {
	if cached.Backend != definitions.BackendPlugin {
		if backend.IsPluginPasswordCacheName(cacheName) {
			return false, nil
		}

		applyPositivePasswordCacheResult(target, cached, authenticated)

		return true, nil
	}

	if !authenticated || auth.Request.NoAuth {
		return false, nil
	}

	restored, ok, err := auth.restorePluginPositiveCache(cacheName, cached)
	if err != nil || !ok {
		return false, err
	}

	*target = *restored
	PutPassDBResultToPool(restored)

	return true, nil
}
