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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	bf "github.com/croessner/nauthilus/v3/server/model/bruteforce"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

const bruteForceListAccountIP = "203.0.113.10"

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

func TestListBlockedIPAddressesUsesIndexWithoutKeyspaceScan(t *testing.T) {
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

	banKey := rediscli.GetBruteForceBanKey(prefix, network)
	shardEntries := map[byte][]redis.Z{
		rediscli.GetBanIndexShard(network): {{Score: float64(time.Now().Add(-time.Hour).Unix()), Member: network}},
	}
	expectPagedBanIndexRead(mock, prefix, 0, -1, shardEntries)
	mock.ExpectGet(banKey).SetVal(bucketName)
	mock.ExpectTTL(banKey).SetVal(ttl)

	result, err := listBlockedIPAddresses(t.Context(), deps, nil, bruteForceListPageQuery{}, "test-guid")

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

func TestBruteForceListGETUsesPagedRedisReads(t *testing.T) {
	const (
		bucketName      = "b_1m_ipv6_128_mail"
		selectedNetwork = "2001:db8::2/128"
	)

	cfg := setupBruteForceListTestConfig(t, bucketName, time.Hour)
	router, mock := newBruteForceListTestRouter(t, cfg)
	prefix := cfg.GetServer().GetRedis().GetPrefix()

	mock.MatchExpectationsInOrder(false)

	expectPagedBanIndexRead(mock, prefix, 0, 2, map[byte][]redis.Z{
		0: {{Score: 100, Member: "2001:db8::1/128"}},
		1: {{Score: 200, Member: selectedNetwork}},
		2: {{Score: 300, Member: "2001:db8::3/128"}},
	})
	mock.ExpectGet(rediscli.GetBruteForceBanKey(prefix, selectedNetwork)).SetVal(bucketName)
	mock.ExpectTTL(rediscli.GetBruteForceBanKey(prefix, selectedNetwork)).SetVal(30 * time.Minute)
	mock.ExpectZRange(rediscli.GetAffectedAccountsIndexKey(prefix), 1, 2).SetVal([]string{})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/bruteforce/list?limit=1&offset=1", nil)
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)

	ipPayload, accountPayload := decodeBruteForceListPayloads(t, recorder)
	assert.Len(t, ipPayload.Entries, 1)
	assert.Equal(t, selectedNetwork, ipPayload.Entries[0].Network)
	assert.NotNil(t, ipPayload.Page)
	assert.Equal(t, 1, ipPayload.Page.Limit)
	assert.Equal(t, 1, ipPayload.Page.Offset)
	assert.Equal(t, 2, ipPayload.Page.NextOffset)
	assert.True(t, ipPayload.Page.HasMore)
	assert.NotNil(t, accountPayload.Page)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBruteForceListAccountsUsePagedIndex(t *testing.T) {
	const (
		bucketName  = "b_1m_ipv6_128_mail"
		accountName = "alice@example.test"
	)

	cfg := setupBruteForceListTestConfig(t, bucketName, time.Hour)
	router, mock := newBruteForceListTestRouter(t, cfg)
	prefix := cfg.GetServer().GetRedis().GetPrefix()

	mock.MatchExpectationsInOrder(false)

	expectPagedBanIndexRead(mock, prefix, 0, 1, nil)
	mock.ExpectZRange(rediscli.GetAffectedAccountsIndexKey(prefix), 0, 1).SetVal([]string{accountName, "bob@example.test"})
	mock.ExpectSMembers(prefix + definitions.RedisPWHistIPsKey + ":" + accountName).SetVal([]string{bruteForceListAccountIP})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/bruteforce/list?limit=1", nil)
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)

	_, accountPayload := decodeBruteForceListPayloads(t, recorder)
	assert.Equal(t, map[string][]string{accountName: []string{bruteForceListAccountIP}}, accountPayload.Accounts)
	assert.NotNil(t, accountPayload.Page)
	assert.Equal(t, 1, accountPayload.Page.Limit)
	assert.Equal(t, 0, accountPayload.Page.Offset)
	assert.Equal(t, 1, accountPayload.Page.NextOffset)
	assert.True(t, accountPayload.Page.HasMore)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBruteForceListPOSTEmptyBodyUsesUnfilteredPagedRequest(t *testing.T) {
	const bucketName = "b_1m_ipv6_128_mail"

	cfg := setupBruteForceListTestConfig(t, bucketName, time.Hour)
	router, mock := newBruteForceListTestRouter(t, cfg)
	prefix := cfg.GetServer().GetRedis().GetPrefix()

	mock.MatchExpectationsInOrder(false)

	expectPagedBanIndexRead(mock, prefix, 0, 1, nil)
	mock.ExpectZRange(rediscli.GetAffectedAccountsIndexKey(prefix), 0, 1).SetVal([]string{})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/bruteforce/list?limit=1", nil)
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBruteForceListPOSTIPFilterUsesTargetedBanKeys(t *testing.T) {
	const (
		bucketName      = "b_1m_ipv6_128_mail"
		selectedNetwork = "2001:db8::2/128"
	)

	cfg := setupBruteForceListTestConfig(t, bucketName, time.Hour)
	router, mock := newBruteForceListTestRouter(t, cfg)
	prefix := cfg.GetServer().GetRedis().GetPrefix()

	mock.MatchExpectationsInOrder(false)

	mock.ExpectGet(rediscli.GetBruteForceBanKey(prefix, selectedNetwork)).SetVal(bucketName)
	mock.ExpectTTL(rediscli.GetBruteForceBanKey(prefix, selectedNetwork)).SetVal(30 * time.Minute)
	mock.ExpectZRange(rediscli.GetAffectedAccountsIndexKey(prefix), 0, 1).SetVal([]string{})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/bruteforce/list?limit=1",
		strings.NewReader(`{"ip_addresses":["2001:db8::2"]}`),
	)
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)

	ipPayload, _ := decodeBruteForceListPayloads(t, recorder)
	assert.Len(t, ipPayload.Entries, 1)
	assert.Equal(t, selectedNetwork, ipPayload.Entries[0].Network)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBruteForceListRejectsInvalidOffset(t *testing.T) {
	const bucketName = "b_1m_ipv6_128_mail"

	cfg := setupBruteForceListTestConfig(t, bucketName, time.Hour)
	router, mock := newBruteForceListTestRouter(t, cfg)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/bruteforce/list?limit=1&offset=-1", nil)
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func newBruteForceListTestRouter(t *testing.T, cfg config.File) (*gin.Engine, redismock.ClientMock) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, mock := redismock.NewClientMock()
	router := gin.New()
	router.GET("/api/v1/bruteforce/list", NewBruteForceListHandler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), rediscli.NewTestClient(db)))
	router.POST("/api/v1/bruteforce/list", NewBruteForceListHandler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), rediscli.NewTestClient(db)))

	return router, mock
}

func expectPagedBanIndexRead(mock redismock.ClientMock, prefix string, start, stop int64, shardEntries map[byte][]redis.Z) {
	for shard := range definitions.BanIndexShardCount {
		key := rediscli.GetBruteForceBanIndexShardKey(prefix, byte(shard))
		mock.ExpectZRangeWithScores(key, start, stop).SetVal(shardEntries[byte(shard)])
	}
}

type bruteForceListIPPayload struct {
	Entries []bf.BanEntry             `json:"entries"`
	Page    *bruteForceListPageResult `json:"page"`
}

type bruteForceListAccountPayload struct {
	Accounts map[string][]string       `json:"accounts"`
	Page     *bruteForceListPageResult `json:"page"`
}

type bruteForceListPageResult struct {
	Limit      int  `json:"limit"`
	Offset     int  `json:"offset"`
	NextOffset int  `json:"next_offset"`
	HasMore    bool `json:"has_more"`
}

func decodeBruteForceListPayloads(t *testing.T, recorder *httptest.ResponseRecorder) (bruteForceListIPPayload, bruteForceListAccountPayload) {
	t.Helper()

	var envelope struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode brute-force envelope: %v", err)
	}

	if len(envelope.Result) != 2 {
		t.Fatalf("brute-force result entries = %d, want 2", len(envelope.Result))
	}

	var ipPayload bruteForceListIPPayload
	if err := json.Unmarshal(envelope.Result[0], &ipPayload); err != nil {
		t.Fatalf("decode blocked IP payload: %v", err)
	}

	var accountPayload bruteForceListAccountPayload
	if err := json.Unmarshal(envelope.Result[1], &accountPayload); err != nil {
		t.Fatalf("decode blocked account payload: %v", err)
	}

	return ipPayload, accountPayload
}
