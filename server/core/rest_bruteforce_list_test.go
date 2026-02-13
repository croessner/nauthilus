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
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func setupBruteForceListTestConfig(t *testing.T, bucketName string, banTime time.Duration) config.File {
	t.Helper()

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{Prefix: "t:"},
		},
		BruteForce: &config.BruteForceSection{
			Buckets: []config.BruteForceRule{
				{
					Name:           bucketName,
					Period:         time.Minute,
					BanTime:        banTime,
					CIDR:           128,
					IPv6:           true,
					FailedRequests: 10,
				},
			},
		},
	}

	config.SetTestFile(cfg)
	SetDefaultConfigFile(config.GetFile())
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	return cfg
}

func TestListBlockedIPAddresses_FallbackScan(t *testing.T) {
	const bucketName = "b_1m_ipv6_128_mail"
	const network = "2a05:aec0:abcd:1::4711/128"

	banTime := 2 * time.Hour
	ttl := time.Hour

	cfg := setupBruteForceListTestConfig(t, bucketName, banTime)
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	deps := restAdminDeps{Cfg: cfg, Logger: logger, Redis: redisClient}
	prefix := cfg.GetServer().GetRedis().GetPrefix()

	for _, key := range rediscli.GetAllBruteForceBanIndexKeys(prefix) {
		mock.ExpectZRangeWithScores(key, 0, -1).SetVal([]redis.Z{})
	}

	banKey := rediscli.GetBruteForceBanKey(prefix, network)
	scanPattern := rediscli.GetBruteForceBanKeyPattern(prefix)
	mock.ExpectScan(0, scanPattern, bruteForceBanScanCount).SetVal([]string{banKey}, 0)
	mock.ExpectGet(banKey).SetVal(bucketName)
	mock.ExpectTTL(banKey).SetVal(ttl)

	result, err := listBlockedIPAddresses(t.Context(), deps, nil, "test-guid")

	if assert.NoError(t, err) {
		assert.NotNil(t, result)
	}

	if assert.NotNil(t, result) && assert.Len(t, result.Entries, 1) {
		entry := result.Entries[0]

		assert.Equal(t, network, entry.Network)
		assert.Equal(t, bucketName, entry.Bucket)
		assert.Equal(t, banTime, entry.BanTime)
		assert.Equal(t, ttl, entry.TTL)
		assert.WithinDuration(t, time.Now().Add(-(banTime - ttl)), entry.BannedAt, 2*time.Second)
	}

	assert.NoError(t, mock.ExpectationsWereMet())
}
