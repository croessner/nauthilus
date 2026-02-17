// Copyright (C) 2024-2025 Christian Rößner
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

package auth

import (
	"strings"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
)

// DefaultCacheService implements core.CacheService in the auth subpackage.
// It mirrors the legacy behavior: on success, write a PositivePasswordCache to Redis.
// On failure, there is no Redis write here (brute-force bookkeeping is handled elsewhere).
//
//goland:nointerface
type DefaultCacheService struct{}

// OnSuccess updates the positive cache after a successful authentication attempt for the specified account name.
func (DefaultCacheService) OnSuccess(auth *core.AuthState, accountName string) error {
	if auth == nil || auth.Request.Protocol == nil || accountName == "" {
		return nil
	}

	if auth.Request.NoAuth || auth.GetPassword().IsZero() {
		return nil
	}

	usedBackend, err := auth.GetUsedCacheBackend()
	if err != nil {
		return err
	}

	cacheName, err := auth.GetCacheNameFor(usedBackend)
	if err != nil {
		return err
	}

	ppc := auth.CreatePositivePasswordCache()
	var sb strings.Builder

	sb.WriteString(auth.Cfg().GetServer().GetRedis().GetPrefix())
	sb.WriteString(definitions.RedisUserPositiveCachePrefix)
	sb.WriteString(cacheName)
	sb.WriteByte(':')
	sb.WriteString(accountName)

	key := sb.String()

	// Write hash with TTL
	backend.SaveUserDataToRedis(auth.Ctx(), auth.Cfg(), auth.Logger(), auth.Redis(), auth.Runtime.GUID, key, auth.Cfg().GetServer().GetRedis().GetPosCacheTTL(), ppc)

	// Metric is incremented inside SaveUserDataToRedis; keep a debug log here for parity
	level.Debug(auth.Logger()).Log(
		definitions.LogKeyGUID, auth.Runtime.GUID,
		definitions.LogKeyMsg, "Stored positive cache to redis",
	)

	return nil
}

// OnFailure handles the actions required in case of an unsuccessful authentication attempt for the given account name.
// No negative cache is written here (historic behavior); brute-force metrics are handled by other parts of the pipeline.
func (DefaultCacheService) OnFailure(_ *core.AuthState, _ string) {
	// Intentionally no-op
}

// Purge removes all cached entries for the specified username.
func (DefaultCacheService) Purge(auth *core.AuthState, username string) {
	if auth == nil || username == "" {
		return
	}

	useCache := false

	for _, backendType := range auth.Cfg().GetServer().GetBackends() {
		if backendType.Get() == definitions.BackendCache {
			useCache = true

			break
		}
	}

	if !useCache {
		return
	}

	// We try to purge for the username itself and for any mapped account name
	namesToPurge := config.NewStringSet()
	(&namesToPurge).Set(username)

	protocols := auth.Cfg().GetAllProtocols()

	for _, protocol := range protocols {
		accountName, err := backend.LookupUserAccountFromRedis(auth.Ctx(), auth.Cfg(), auth.Redis(), username, protocol, "")
		if err == nil && accountName != "" {
			(&namesToPurge).Set(accountName)
		}
	}

	userKeys := config.NewStringSet()

	for _, protocol := range protocols {
		cacheNames := backend.GetCacheNames(auth.Cfg(), auth.Channel(), protocol, definitions.CacheAll)

		for _, cacheName := range (&cacheNames).GetStringSlice() {
			for _, name := range (&namesToPurge).GetStringSlice() {
				var sb strings.Builder

				sb.WriteString(auth.Cfg().GetServer().GetRedis().GetPrefix())
				sb.WriteString(definitions.RedisUserPositiveCachePrefix)
				sb.WriteString(cacheName)
				sb.WriteByte(':')
				sb.WriteString(name)

				(&userKeys).Set(sb.String())
			}
		}
	}

	for _, userKey := range (&userKeys).GetStringSlice() {
		_, _ = auth.Redis().GetWriteHandle().Del(auth.Ctx(), userKey).Result()
	}
}
