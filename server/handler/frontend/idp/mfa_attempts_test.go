package idp

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// configureMFAAttemptTestStorage supplies isolated real script semantics for browser verification tests.
func configureMFAAttemptTestStorage(t *testing.T, handler *FrontendHandler) {
	t.Helper()
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})

	t.Cleanup(func() { _ = client.Close() })

	if handler.deps == nil {
		handler.deps = &deps.Deps{Cfg: &mockFrontendCfg{}}
	}

	handler.deps.Redis = rediscli.NewTestClient(client)
}
