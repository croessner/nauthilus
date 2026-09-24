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

// Package redisroundtrip records Redis network round trips issued through go-redis clients in tests.
package redisroundtrip

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/redis/go-redis/v9"
)

// handshakeCommands are issued by go-redis while initializing pooled connections and are not request work.
var handshakeCommands = []string{"hello", "client", "auth", "select", "readonly"}

// Recorder is a go-redis hook that records every standalone command and every pipeline as one round trip.
//
// Attach it to a client backed by miniredis to prove how many sequential network round trips a code path
// needs. Connection handshake commands are ignored because go-redis issues them independently of callers.
type Recorder struct {
	mu    sync.Mutex
	trips [][]string
}

var _ redis.Hook = (*Recorder)(nil)

// Attach registers a new recorder on a go-redis client.
func Attach(client redis.UniversalClient) *Recorder {
	recorder := &Recorder{}
	client.AddHook(recorder)

	return recorder
}

// DialHook leaves connection setup untouched.
func (r *Recorder) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

// ProcessHook records one standalone command as one round trip.
func (r *Recorder) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		r.record([]redis.Cmder{cmd})

		return next(ctx, cmd)
	}
}

// ProcessPipelineHook records one pipeline, including all queued commands, as one round trip.
func (r *Recorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		r.record(cmds)

		return next(ctx, cmds)
	}
}

// RoundTrips returns the lowercase command names of every recorded round trip in execution order.
func (r *Recorder) RoundTrips() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()

	trips := make([][]string, len(r.trips))
	for i := range r.trips {
		trips[i] = slices.Clone(r.trips[i])
	}

	return trips
}

// Count returns the number of recorded round trips.
func (r *Recorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.trips)
}

// Reset forgets all recorded round trips, for example after test setup such as script uploads.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.trips = nil
}

// record stores the command names of one round trip unless it only initializes a connection.
func (r *Recorder) record(cmds []redis.Cmder) {
	names := make([]string, 0, len(cmds))
	handshakeOnly := true

	for _, cmd := range cmds {
		name := strings.ToLower(cmd.Name())
		if !slices.Contains(handshakeCommands, name) {
			handshakeOnly = false
		}

		names = append(names, name)
	}

	if handshakeOnly {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.trips = append(r.trips, names)
}
