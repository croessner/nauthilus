package bruteforce

import (
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// Test-only adapter: delegate each call to the current global redis client.
//
// Many tests in this package swap the global client via `rediscli.NewTestClient(db)`.
// The hard-fail default seam requires a non-nil default client.
type globalTestClient struct{}

var _ rediscli.Client = globalTestClient{}

func (globalTestClient) GetWriteHandle() redis.UniversalClient {
	return rediscli.GetClient().GetWriteHandle()
}

func (globalTestClient) GetReadHandle() redis.UniversalClient {
	return rediscli.GetClient().GetReadHandle()
}

func (globalTestClient) GetWritePipeline() redis.Pipeliner {
	return rediscli.GetClient().GetWritePipeline()
}

func (globalTestClient) GetReadPipeline() redis.Pipeliner {
	return rediscli.GetClient().GetReadPipeline()
}

func (globalTestClient) Close() {}

func (globalTestClient) GetSecurityManager() *rediscli.SecurityManager {
	return rediscli.GetClient().GetSecurityManager()
}

func init() {
	SetDefaultRedisClient(globalTestClient{})
}
