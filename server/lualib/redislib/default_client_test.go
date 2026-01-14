// Copyright (C) 2026 Christian Rößner
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

package redislib

import (
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// globalTestClient is a test-only adapter that delegates each call to the
// current `rediscli.GetClient()` instance.
//
// Tests in this package frequently call `rediscli.NewTestClient(db)` to swap the
// underlying global test conn. If we stored the returned interface value
// directly, it would not automatically follow later swaps.
//
// This adapter keeps tests compatible with hard-fail semantics in
// `getDefaultClient()` by ensuring a non-nil default client is always configured.
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

func init() {
	SetDefaultClient(globalTestClient{})
}
