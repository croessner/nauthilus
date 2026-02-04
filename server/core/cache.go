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
	"strings"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/definitions"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"go.opentelemetry.io/otel/attribute"
)

// CachePassDB implements the redis password database backend.
func CachePassDB(auth *AuthState) (passDBResult *PassDBResult, err error) {
	// Root span for cache backend lookup
	tr := monittrace.New("nauthilus/cache_backend")
	ctx, sp := tr.Start(auth.Ctx(), "cache.passdb",
		attribute.String("service", auth.Request.Service),
		attribute.String("username", auth.Request.Username),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = ctx

	defer sp.End()

	var (
		accountName string
		ppc         *bktype.PositivePasswordCache
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, auth.Request.Service)
	stopTimer := stats.PrometheusTimer(auth.Cfg(), definitions.PromBackend, "cache_backend_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	passDBResult = GetPassDBResultFromPool()

	accountName, err = auth.updateUserAccountInRedis()
	if err != nil {
		sp.RecordError(err)

		return
	}

	if accountName != "" {
		cacheNames := backend.GetCacheNames(auth.Cfg(), auth.Channel(), auth.Request.Protocol.Get(), definitions.CacheAll)

		for _, cacheName := range cacheNames.GetStringSlice() {
			// Child span per cache name read attempt
			cctx, csp := tr.Start(auth.Ctx(), "cache.get",
				attribute.String("cache_name", cacheName),
			)

			_ = cctx

			var sb strings.Builder

			sb.WriteString(auth.cfg().GetServer().GetRedis().GetPrefix())
			sb.WriteString(definitions.RedisUserPositiveCachePrefix)
			sb.WriteString(cacheName)
			sb.WriteByte(':')
			sb.WriteString(accountName)

			redisPosUserKey := sb.String()

			ppc = &bktype.PositivePasswordCache{}

			isRedisErr := false
			if isRedisErr, err = backend.LoadCacheFromRedisWithSF(auth.Ctx(), auth.Cfg(), auth.Logger(), auth.deps.Redis, redisPosUserKey, ppc); err != nil {
				csp.RecordError(err)

				csp.End()

				return
			}

			// The user was not found for the current cache name
			if isRedisErr {
				csp.SetAttributes(attribute.Bool("hit", false))
				csp.End()

				continue
			}

			passDBResult.UserFound = true
			passDBResult.AccountField = ppc.AccountField
			passDBResult.TOTPSecretField = ppc.TOTPSecretField
			passDBResult.UniqueUserIDField = ppc.UniqueUserIDField
			passDBResult.DisplayNameField = ppc.DisplayNameField
			passDBResult.Backend = ppc.Backend
			passDBResult.Attributes = ppc.Attributes

			if auth.Request.NoAuth || ppc.Password == util.GetHash(util.PreparePassword(auth.Request.Password)) {
				passDBResult.Authenticated = true
			}

			csp.SetAttributes(
				attribute.Bool("hit", true),
				attribute.Bool("authenticated", passDBResult.Authenticated),
			)
			csp.End()

			break
		}
	}

	return
}
