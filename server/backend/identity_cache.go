package backend

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/stats"
	"github.com/croessner/nauthilus/v4/server/util"
	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
)

// IdentityCache stores encrypted identity snapshots independently of password evidence.
// Its persistent prefix-wide epoch fences lookups started before administrative invalidation.
type IdentityCache struct {
	cfg    config.File
	client rediscli.Client
}

// identityCacheEnvelope binds an encrypted snapshot to its exact scope and invalidation epoch.
type identityCacheEnvelope struct {
	Generation string `json:"generation"`
	Scope      string `json:"scope"`
	Data       []byte `json:"data"`
}

// NewIdentityCache constructs a cache using the injected Redis authority and encryption manager.
func NewIdentityCache(cfg config.File, client rediscli.Client) *IdentityCache {
	return &IdentityCache{cfg: cfg, client: client}
}

// IdentityCacheKey identifies one username in a configured backend cache namespace.
// Different lookup contexts replace this entry and must pass the separate scope check.
func IdentityCacheKey(prefix, cacheName, username string) string {
	return prefix + "UCI:" + cacheName + ":" + username
}

// epochKey identifies the persistent fence, which must never be expired or reused.
func (c *IdentityCache) epochKey() string {
	return c.cfg.GetServer().GetRedis().GetPrefix() + "UCI:epoch"
}

// Generation captures the authority epoch before a lookup and safely initializes a missing epoch.
func (c *IdentityCache) Generation(ctx context.Context) (string, error) {
	ctx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, c.cfg)
	defer cancel()

	epoch, err := c.client.GetWriteHandle().Get(ctx, c.epochKey()).Result()
	if !errors.Is(err, redis.Nil) {
		return epoch, err
	}

	if err = c.client.GetWriteHandle().SetNX(ctx, c.epochKey(), rand.Text(), 0).Err(); err != nil {
		return "", err
	}

	return c.client.GetWriteHandle().Get(ctx, c.epochKey()).Result()
}

// Invalidate fences every identity entry, including concurrent first lookups of unknown aliases.
// Broad invalidation is deliberate: canonical identity may be unknown until LDAP returns.
func (c *IdentityCache) Invalidate(ctx context.Context) error {
	ctx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, c.cfg)
	defer cancel()

	return c.client.GetWriteHandle().Set(ctx, c.epochKey(), rand.Text(), 0).Err()
}

// Load reads both snapshot and epoch from the writer to avoid accepting stale replica state.
func (c *IdentityCache) Load(ctx context.Context, key, scope string) ([]byte, error) {
	ctx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, c.cfg)
	defer cancel()
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	value, err := c.client.GetWriteHandle().Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	epoch, err := c.client.GetWriteHandle().Get(ctx, c.epochKey()).Result()
	if err != nil {
		return nil, err
	}

	plaintext, err := c.client.GetSecurityManager().Decrypt(value)
	if err != nil {
		return nil, err
	}

	var entry identityCacheEnvelope
	if err = jsoniter.ConfigFastest.UnmarshalFromString(plaintext, &entry); err != nil {
		return nil, err
	}

	if epoch == "" || entry.Generation != epoch || entry.Scope != scope {
		return nil, nil
	}

	return entry.Data, nil
}

// encode serializes and encrypts a snapshot without exposing cached attributes in Redis.
func (c *IdentityCache) encode(epoch, scope string, data []byte) (string, error) {
	value, err := jsoniter.ConfigFastest.MarshalToString(identityCacheEnvelope{Generation: epoch, Scope: scope, Data: data})
	if err != nil {
		return "", err
	}

	return c.client.GetSecurityManager().Encrypt(value)
}

// Store publishes the immutable snapshot with its original epoch and an atomic fixed TTL.
// A concurrent flush can leave an old-epoch entry, but Load will never accept that entry.
func (c *IdentityCache) Store(ctx context.Context, key, epoch, scope string, data []byte, ttl time.Duration) error {
	if epoch == "" || ttl <= 0 {
		return nil
	}

	value, err := c.encode(epoch, scope, data)
	if err != nil {
		return err
	}

	ctx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, c.cfg)
	defer cancel()
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	return c.client.GetWriteHandle().Set(ctx, key, value, ttl).Err()
}
