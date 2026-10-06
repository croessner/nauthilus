package backend

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/security"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

// newIdentityCacheTest constructs an isolated encrypted Redis cache fixture.
func newIdentityCacheTest(t *testing.T) (*IdentityCache, redismock.ClientMock) {
	t.Helper()

	db, mock := redismock.NewClientMock()
	cfg := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:"}}}
	client := rediscli.NewTestClientWithSecurity(db, security.NewManager(secret.New("1234567890123456")))

	return NewIdentityCache(cfg, client), mock
}

// TestIdentityCacheFlushRejectsPreFlushLookup rejects a delayed snapshot from before a completed flush.
func TestIdentityCacheFlushRejectsPreFlushLookup(t *testing.T) {
	cache, mock := newIdentityCacheTest(t)
	ctx := context.Background()

	mock.ExpectGet("test:UCI:epoch").SetVal("before")

	epoch, err := cache.Generation(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "before", epoch)
	// A delayed backend completion may write its old snapshot after a flush.
	payload, err := cache.encode(epoch, "scope", []byte(`{"account":"alice"}`))
	assert.NoError(t, err)
	mock.ExpectGet("test:UCI:mail:alice").SetVal(payload)
	mock.ExpectGet("test:UCI:epoch").SetVal("after")

	data, err := cache.Load(ctx, "test:UCI:mail:alice", "scope")
	assert.NoError(t, err)
	assert.Nil(t, data)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestIdentityCacheScopeAndReadFailure accepts only matching scopes with a readable current generation.
func TestIdentityCacheScopeAndReadFailure(t *testing.T) {
	for _, tc := range []struct {
		name, scope  string
		missingEpoch bool
	}{
		{name: "matching scope", scope: "scope"},
		{name: "different client", scope: "other"},
		{name: "missing epoch", scope: "scope", missingEpoch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, mock := newIdentityCacheTest(t)
			payload, err := cache.encode("epoch", "scope", []byte(`{"account":"alice"}`))
			assert.NoError(t, err)
			mock.ExpectGet("entry").SetVal(payload)

			if tc.missingEpoch {
				mock.ExpectGet("test:UCI:epoch").RedisNil()
			} else {
				mock.ExpectGet("test:UCI:epoch").SetVal("epoch")
			}

			data, err := cache.Load(context.Background(), "entry", tc.scope)
			if tc.missingEpoch {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tc.scope == "scope" && !tc.missingEpoch {
				assert.JSONEq(t, `{"account":"alice"}`, string(data))
			} else {
				assert.Nil(t, data)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestIdentityCacheStoreUsesAtomicTTL requires a single expiring write for each snapshot.
func TestIdentityCacheStoreUsesAtomicTTL(t *testing.T) {
	cache, mock := newIdentityCacheTest(t)
	mock.Regexp().ExpectSet("entry", ".+", time.Minute).SetVal("OK")
	assert.NoError(t, cache.Store(context.Background(), "entry", "epoch", "scope", []byte(`{}`), time.Minute))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestIdentityCacheEpochCreationAndInvalidation verifies persistent generation initialization and rotation.
func TestIdentityCacheEpochCreationAndInvalidation(t *testing.T) {
	cache, mock := newIdentityCacheTest(t)
	ctx := context.Background()

	mock.ExpectGet("test:UCI:epoch").RedisNil()
	mock.Regexp().ExpectSetNX("test:UCI:epoch", ".+", 0).SetVal(true)
	mock.ExpectGet("test:UCI:epoch").SetVal("new-epoch")

	epoch, err := cache.Generation(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "new-epoch", epoch)
	mock.Regexp().ExpectSet("test:UCI:epoch", ".+", 0).SetVal("OK")
	assert.NoError(t, cache.Invalidate(ctx))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestIdentityCacheLoadExpiredEntry treats expired Redis entries as misses.
func TestIdentityCacheLoadExpiredEntry(t *testing.T) {
	cache, mock := newIdentityCacheTest(t)
	mock.ExpectGet("entry").RedisNil()

	data, err := cache.Load(context.Background(), "entry", "scope")
	assert.NoError(t, err)
	assert.Nil(t, data)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestPositiveCacheKeysIncludesDisabledIdentityCacheWithoutChannels retains invalidation keys when local caching is disabled.
func TestPositiveCacheKeysIncludesDisabledIdentityCacheWithoutChannels(t *testing.T) {
	cfg := &config.FileSettings{Server: &config.ServerSection{}, LDAP: &config.LDAPSection{Search: []config.LDAPSearchProtocol{{CacheName: "mail"}}}}

	keys := PositiveCacheKeys(cfg, nil, "test:", []string{"jmap"}, []string{"alias", "account"})
	for _, name := range []string{"alias", "account"} {
		assert.Contains(t, keys, IdentityCacheKey("test:", "mail", name))
		assert.Contains(t, keys, PositivePasswordCacheKey("test:", "__default__", name))
	}
}
