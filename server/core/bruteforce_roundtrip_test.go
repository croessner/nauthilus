// Copyright (C) 2026 Christian Rößner
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
	"reflect"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/testing/redisroundtrip"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// bruteForceRoundTripFixture runs brute-force accounting of one request against miniredis.
type bruteForceRoundTripFixture struct {
	auth     *AuthState
	ctx      *gin.Context
	storage  *miniredis.Miniredis
	recorder *redisroundtrip.Recorder
}

// newBruteForceRoundTripFixture creates a known-account request with reputation tracking on miniredis.
func newBruteForceRoundTripFixture(t *testing.T, cfg *config.FileSettings) *bruteForceRoundTripFixture {
	t.Helper()

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	storage := miniredis.RunT(t)
	db := redis.NewClient(&redis.Options{Addr: storage.Addr()})

	t.Cleanup(func() { _ = db.Close() })

	redisClient := rediscli.NewTestClient(db)
	auth.deps.Redis = redisClient
	auth.deps.Tolerate = tolerate.NewTolerateWithDeps(cfg, auth.Logger(), redisClient, 0)

	rediscli.ClearScriptCache()

	if err := rediscli.UploadAllScripts(t.Context(), auth.Logger(), redisClient); err != nil {
		t.Fatalf("upload scripts: %v", err)
	}

	field := accountcache.GetAccountMappingField(auth.Request.Username, auth.Request.Protocol.Get(), "")
	storage.HSet(rediscli.GetUserHashKey(cfg.Server.Redis.Prefix, auth.Request.Username), field, auth.Request.Username)

	return &bruteForceRoundTripFixture{
		auth:     auth,
		ctx:      ctx,
		storage:  storage,
		recorder: redisroundtrip.Attach(db),
	}
}

func TestCheckBruteForceUsesTwoRedisRoundTrips(t *testing.T) {
	fixture := newBruteForceRoundTripFixture(t, hardCutBruteForceConfig(t))

	if fixture.auth.CheckBruteForce(fixture.ctx) {
		t.Fatal("clean request was blocked")
	}

	want := [][]string{
		{"hget"},                      // account mapping, outside brute-force accounting
		{"evalsha", "exists", "hget"}, // RWP precheck, cached ban and reputation
		{"evalsha"},                   // bucket counters
	}

	if trips := fixture.recorder.RoundTrips(); !reflect.DeepEqual(trips, want) {
		t.Fatalf("CheckBruteForce round trips = %v, want %v", trips, want)
	}

	if fixture.auth.Runtime.BruteForceError || fixture.auth.Runtime.BFRWP {
		t.Fatalf("runtime = error:%t rwp:%t, want a clean enforced request",
			fixture.auth.Runtime.BruteForceError, fixture.auth.Runtime.BFRWP)
	}
}
