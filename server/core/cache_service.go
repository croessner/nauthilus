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
	"strconv"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
)

// CacheService abstracts positive/negative cache behavior.
type CacheService interface {
	// OnSuccess updates the positive cache after a successful authentication attempt for the specified account name.
	OnSuccess(ctx *gin.Context, a *AuthState, accountName string) error

	// OnFailure handles the actions required in case of an unsuccessful authentication attempt for the given account name.
	OnFailure(ctx *gin.Context, a *AuthState, accountName string)
}

// DefaultCacheService preserves the legacy behavior currently implemented inside AuthState.
type DefaultCacheService struct{}

var defaultCacheService CacheService = DefaultCacheService{}

// OnSuccess processes actions upon successful authentication, including caching user data in Redis for positive matches.
func (DefaultCacheService) OnSuccess(ctx *gin.Context, a *AuthState, accountName string) error {
	usedBackend, err := a.getUsedBackend()
	if err != nil {
		return err
	}

	cacheName, err := a.getCacheName(usedBackend)
	if err != nil {
		return err
	}

	ppc := a.createPositivePasswordCache()
	if accountName == "" || ppc.Password == "" {
		return nil
	}

	redisUserKey := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserPositiveCachePrefix + cacheName + ":" + accountName

	go func() {
		reqCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		backend.SaveUserDataToRedis(reqCtx, a.GUID, redisUserKey, config.GetFile().GetServer().Redis.PosCacheTTL, ppc)
	}()

	// legacy local cache set after successful auth will still happen in caller
	_ = ctx

	return nil
}

// OnFailure handles actions following a failed authentication attempt, including logging and incrementing failure counters.
func (DefaultCacheService) OnFailure(ctx *gin.Context, a *AuthState, accountName string) {
	// logic from processCacheUserLoginFail
	util.DebugModule(
		definitions.DbgAuth,
		definitions.LogKeyGUID, a.GUID,
		"account", accountName,
		"authenticated", false,
		definitions.LogKeyMsg, "Calling saveFailedPasswordCounterInRedis()",
	)

	ttl := time.Second
	argTTL := strconv.FormatInt(int64(ttl.Seconds()), 10)
	burstKey := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBFBurstPrefix + a.sfKeyHash()

	if res, err := rediscli.ExecuteScript(ctx, "IncrementAndExpire", rediscli.LuaScripts["IncrementAndExpire"], []string{burstKey}, argTTL); err == nil {
		if v, ok := res.(int64); ok && v == 1 {
			// leader
			bruteforce.NewBucketManager(ctx.Request.Context(), a.GUID, a.ClientIP).
				WithUsername(a.Username).
				WithPassword(a.Password).
				WithAccountName(accountName).
				SaveFailedPasswordCounterInRedis()

			a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "bf_burst_leader")
		} else {
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "bf_burst_follower")
		}
	} else {
		// Fail-open: still count, but log error as follower for visibility
		bruteforce.NewBucketManager(ctx.Request.Context(), a.GUID, a.ClientIP).
			WithUsername(a.Username).
			WithPassword(a.Password).
			WithAccountName(accountName).
			SaveFailedPasswordCounterInRedis()

		a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "bf_burst_follower")
	}
}
