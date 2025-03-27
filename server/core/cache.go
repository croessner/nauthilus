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
	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
)

// CachePassDB implements the redis password database backend.
func CachePassDB(auth *AuthState) (passDBResult *PassDBResult, err error) {
	var (
		accountName string
		ppc         *bktype.PositivePasswordCache
	)

	stopTimer := stats.PrometheusTimer(definitions.PromBackend, "cache_backend_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	passDBResult = &PassDBResult{}

	accountName, err = auth.updateUserAccountInRedis()
	if err != nil {
		return
	}

	if accountName != "" {
		cacheNames := backend.GetCacheNames(auth.Protocol.Get(), definitions.CacheAll)

		for _, cacheName := range cacheNames.GetStringSlice() {
			redisPosUserKey := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserPositiveCachePrefix + cacheName + ":" + accountName

			ppc = &bktype.PositivePasswordCache{}

			isRedisErr := false
			if isRedisErr, err = backend.LoadCacheFromRedis(auth.HTTPClientContext, redisPosUserKey, ppc); err != nil {
				return
			}

			// The user was not found for the current cache name
			if isRedisErr {
				continue
			}

			passDBResult.UserFound = true
			passDBResult.AccountField = ppc.AccountField
			passDBResult.TOTPSecretField = ppc.TOTPSecretField
			passDBResult.UniqueUserIDField = ppc.UniqueUserIDField
			passDBResult.DisplayNameField = ppc.DisplayNameField
			passDBResult.Backend = ppc.Backend
			passDBResult.Attributes = ppc.Attributes

			if auth.NoAuth || ppc.Password == util.GetHash(util.PreparePassword(auth.Password)) {
				passDBResult.Authenticated = true
			}

			break
		}
	}

	return
}
