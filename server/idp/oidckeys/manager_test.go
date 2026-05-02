package oidckeys

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/stretchr/testify/assert"
)

func TestManagerUsesConfiguredRedisDeadlines(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Timeouts: config.Timeouts{
				RedisRead: 45 * time.Millisecond,
			},
		},
	}
	manager := NewManager(&deps.Deps{Cfg: cfg})

	readCtx, cancel := manager.redisReadContext(context.Background())
	defer cancel()

	deadline, ok := readCtx.Deadline()

	assert.True(t, ok, "expected Redis read context to carry a deadline")
	assert.WithinDuration(t, time.Now().Add(45*time.Millisecond), deadline, 10*time.Millisecond)
}
