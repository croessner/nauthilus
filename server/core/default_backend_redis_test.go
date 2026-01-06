package core

import (
	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// Ensure backend Redis seam is configured for core package tests.
//
// Core tests import `backend` and may call functions that now require
// `backend.SetDefaultRedisClient(...)` (Stage C hard-fail). Tests commonly swap
// the global redis client via `rediscli.NewTestClient(db)`.
//
// This adapter delegates at call time to the currently active global client so
// swaps remain visible.
type backendGlobalTestClient struct{}

var _ rediscli.Client = backendGlobalTestClient{}

func (backendGlobalTestClient) GetWriteHandle() redis.UniversalClient {
	return rediscli.GetClient().GetWriteHandle()
}

func (backendGlobalTestClient) GetReadHandle() redis.UniversalClient {
	return rediscli.GetClient().GetReadHandle()
}

func (backendGlobalTestClient) GetWritePipeline() redis.Pipeliner {
	return rediscli.GetClient().GetWritePipeline()
}

func (backendGlobalTestClient) GetReadPipeline() redis.Pipeliner {
	return rediscli.GetClient().GetReadPipeline()
}

func (backendGlobalTestClient) Close() {}

func init() {
	backend.SetDefaultRedisClient(backendGlobalTestClient{})
}
