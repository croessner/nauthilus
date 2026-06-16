// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/rediscli"

	"github.com/redis/go-redis/v9"
)

var _ pluginapi.Redis = (*redisFacade)(nil)

// NewRedisFacade exposes read and write handles from the host Redis client.
func NewRedisFacade(client rediscli.Client) pluginapi.Redis {
	if client == nil {
		return nil
	}

	return &redisFacade{client: client}
}

type redisFacade struct {
	client rediscli.Client
}

// Read returns the host-selected read Redis handle.
func (r *redisFacade) Read() redis.Cmdable {
	if r == nil || r.client == nil {
		return nil
	}

	return r.client.GetReadHandle()
}

// Write returns the host write Redis handle.
func (r *redisFacade) Write() redis.Cmdable {
	if r == nil || r.client == nil {
		return nil
	}

	return r.client.GetWriteHandle()
}

// ReadPipeline returns a host read pipeline.
func (r *redisFacade) ReadPipeline() redis.Pipeliner {
	if r == nil || r.client == nil {
		return nil
	}

	return r.client.GetReadPipeline()
}

// WritePipeline returns a host write pipeline.
func (r *redisFacade) WritePipeline() redis.Pipeliner {
	if r == nil || r.client == nil {
		return nil
	}

	return r.client.GetWritePipeline()
}
