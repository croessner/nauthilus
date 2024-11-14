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
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
)

// cachePassDB implements the redis password database backend.
func cachePassDB(auth *AuthState) (passDBResult *PassDBResult, err error) {
	var (
		accountName string
		ppc         *backend.PositivePasswordCache
	)

	stopTimer := stats.PrometheusTimer(global.PromBackend, "cache_backend_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	passDBResult = &PassDBResult{}

	accountName, err = auth.updateUserAccountInRedis()
	if err != nil {
		return
	}

	if accountName != "" {
		cacheNames := backend.GetCacheNames(auth.Protocol.Get(), global.CacheAll)

		for _, cacheName := range cacheNames.GetStringSlice() {
			redisPosUserKey := config.LoadableConfig.Server.Redis.Prefix + "ucp:" + cacheName + ":" + accountName

			ppc = &backend.PositivePasswordCache{}

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

	if !passDBResult.Authenticated {
		if key := auth.getPasswordHistoryRedisHashKey(true); key != "" {
			auth.loadPasswordHistoryFromRedis(key)
		}

		// Prevent password lookups for already known wrong passwords (And the user is unknown in the entire system)
		if auth.PasswordHistory != nil {
			passwordHash := util.GetHash(util.PreparePassword(auth.Password))
			if _, foundPassword := (*auth.PasswordHistory)[passwordHash]; foundPassword {
				passDBResult.UserFound = true
			}
		}
	}

	return
}
