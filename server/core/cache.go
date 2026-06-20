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
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/definitions"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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
		err = auth.loadPositivePasswordCache(tr, accountName, passDBResult)
	}

	return
}

// loadPositivePasswordCache searches configured positive password caches for one account.
func (auth *AuthState) loadPositivePasswordCache(tr monittrace.Tracer, accountName string, passDBResult *PassDBResult) error {
	cacheNames := backend.GetCacheNames(auth.Cfg(), auth.Channel(), auth.Request.Protocol.Get(), definitions.CacheAll)

	for _, cacheName := range cacheNames.GetStringSlice() {
		ppc, found, authenticated, err := auth.readPositivePasswordCache(tr, cacheName, accountName)
		if err != nil {
			return err
		}

		if !found {
			continue
		}

		applyPositivePasswordCacheResult(passDBResult, ppc, authenticated)

		break
	}

	return nil
}

// readPositivePasswordCache loads one positive password cache entry and annotates its span.
func (auth *AuthState) readPositivePasswordCache(tr monittrace.Tracer, cacheName string, accountName string) (*bktype.PositivePasswordCache, bool, bool, error) {
	cctx, csp := tr.Start(auth.Ctx(), "cache.get",
		attribute.String("cache_name", cacheName),
	)

	_ = cctx

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

	authenticated := auth.Request.NoAuth || ppc.Password == auth.cachePasswordHash()
	applyPositivePasswordCacheSpan(csp, authenticated)

	return ppc, true, authenticated, nil
}

// positivePasswordCacheKey builds the Redis key for a positive password cache entry.
func (auth *AuthState) positivePasswordCacheKey(cacheName string, accountName string) string {
	var sb strings.Builder

	sb.WriteString(auth.cfg().GetServer().GetRedis().GetPrefix())
	sb.WriteString(definitions.RedisUserPositiveCachePrefix)
	sb.WriteString(cacheName)
	sb.WriteByte(':')
	sb.WriteString(accountName)

	return sb.String()
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

// cachePasswordHash returns the prepared short hash of the current request password.
func (auth *AuthState) cachePasswordHash() string {
	var pwShort string

	auth.Request.Password.WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		prepared := util.PreparePasswordBytes(value)
		defer clear(prepared)

		pwShort = util.GetHashBytes(prepared)
	})

	return pwShort
}
