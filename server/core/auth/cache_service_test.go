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

package auth

import (
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-redis/redismock/v9"
)

// TestDefaultCacheService_OnSuccess verifies that a positive cache write uses the expected
// Redis key and sets hash fields plus expiry. We rely on GetCacheNames defaulting to
// "__default__" when no specific backend cache names are configured.
func TestDefaultCacheService_OnSuccess_WritesRedisHashAndTTL(t *testing.T) {
	// Minimal config: Redis prefix + TTL; no specific LDAP/Lua cache names so default "__default__" is used
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix:      "nt:",
				PosCacheTTL: 60 * time.Second,
			},
		},
	}
	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(cfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	// Redis mock
	db, mock := redismock.NewClientMock()
	rediscli.NewTestClient(db)

	// Prepare auth state
	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{
		Cfg:    config.GetFile(),
		Logger: log.GetLogger(),
		Redis:  rediscli.GetClient(),
	}).(*core.AuthState)

	auth.GUID = "guid-123"
	auth.Protocol = config.NewProtocol("imap")
	auth.UsedPassDBBackend = definitions.BackendLDAP // will map to CacheLDAP but default cache name applies
	auth.SourcePassDBBackend = definitions.BackendLDAP
	auth.AccountField = "uid"
	auth.Password = "secret"
	auth.Attributes = map[string][]any{"uid": {"acc"}}

	accountName := "acc"
	cacheName := "__default__"
	key := cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisUserPositiveCachePrefix + cacheName + ":" + accountName

	// Build expected hash map matching SaveUserDataToRedis behavior
	attrsJSONBytes, _ := jsoniter.ConfigFastest.Marshal(auth.Attributes)
	expected := map[string]any{
		"backend":       int(definitions.BackendLDAP),
		"password":      util.GetHash(util.PreparePassword(auth.Password)),
		"account_field": auth.AccountField,
		"attributes":    string(attrsJSONBytes),
	}

	// Expect an HSET with the map and an EXPIRE on the computed key
	mock.ExpectHSet(key, expected).SetVal(4)
	mock.ExpectExpire(key, cfg.GetServer().GetRedis().GetPosCacheTTL()).SetVal(true)

	svc := DefaultCacheService{}
	if err := svc.OnSuccess(auth, accountName); err != nil {
		t.Fatalf("OnSuccess returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet redis expectations: %v", err)
	}
}
