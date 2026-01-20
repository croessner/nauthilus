package backend

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestGetUserAccountFromCache_ProtocolMapping(t *testing.T) {
	ctx := context.Background()
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "nauthilus:",
				AccountLocalCache: config.AccountLocalCache{
					Enabled: true,
					TTL:     5 * time.Minute,
					Shards:  1,
				},
			},
		},
	}
	logger := slog.Default()

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	accountCache := accountcache.NewManager(cfg)

	username := "croessner"
	accountIMAP := "de10000@srvint.net"
	accountKeycloak := "croessner_kc"

	key := rediscli.GetUserHashKey(cfg.GetServer().GetRedis().GetPrefix(), username)

	t.Run("IMAP mapping", func(t *testing.T) {
		fieldIMAP := accountcache.GetAccountMappingField(username, "imap", "")
		mock.ExpectHGet(key, fieldIMAP).SetVal(accountIMAP)

		res := GetUserAccountFromCache(ctx, cfg, logger, redisClient, accountCache, username, "imap", "", "guid1")
		assert.Equal(t, accountIMAP, res)
	})

	t.Run("Keycloak mapping", func(t *testing.T) {
		fieldKC := accountcache.GetAccountMappingField(username, "keycloak", "cid123")
		mock.ExpectHGet(key, fieldKC).SetVal(accountKeycloak)

		res := GetUserAccountFromCache(ctx, cfg, logger, redisClient, accountCache, username, "keycloak", "cid123", "guid2")
		assert.Equal(t, accountKeycloak, res)
	})

	t.Run("Local cache hit (IMAP)", func(t *testing.T) {
		// No ExpectHGet here, should hit local cache
		res := GetUserAccountFromCache(ctx, cfg, logger, redisClient, accountCache, username, "imap", "", "guid3")
		assert.Equal(t, accountIMAP, res)
	})

	t.Run("Local cache hit (Keycloak)", func(t *testing.T) {
		// No ExpectHGet here, should hit local cache
		res := GetUserAccountFromCache(ctx, cfg, logger, redisClient, accountCache, username, "keycloak", "cid123", "guid4")
		assert.Equal(t, accountKeycloak, res)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestResolveAccountIdentifier_WithMapping(t *testing.T) {
	ctx := context.Background()
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "nauthilus:",
			},
		},
	}
	logger := slog.Default()
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	username := "user1"
	protocol := "imap"
	account := "acc1"
	key := rediscli.GetUserHashKey(cfg.GetServer().GetRedis().GetPrefix(), username)
	field := accountcache.GetAccountMappingField(username, protocol, "")

	mock.ExpectHGet(key, field).SetVal(account)

	res := ResolveAccountIdentifier(ctx, cfg, logger, redisClient, username, protocol, "", "guid")
	assert.Equal(t, account, res)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestResolveAccountIdentifier_NoMapping(t *testing.T) {
	ctx := context.Background()
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "nauthilus:",
			},
		},
	}
	logger := slog.Default()
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	username := "unknown"
	protocol := "imap"
	key := rediscli.GetUserHashKey(cfg.GetServer().GetRedis().GetPrefix(), username)
	field := accountcache.GetAccountMappingField(username, protocol, "")

	mock.ExpectHGet(key, field).RedisNil()

	res := ResolveAccountIdentifier(ctx, cfg, logger, redisClient, username, protocol, "", "guid")
	// Should return the identifier itself if no mapping is found
	assert.Equal(t, username, res)

	assert.NoError(t, mock.ExpectationsWereMet())
}
