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

// Package rediscluster provides a two-node Redis Cluster test fixture backed by miniredis.
//
// Limitation: miniredis does not own slots, so MOVED and ASK redirections cannot be simulated. The fixture
// proves slot-local keys and per-node splitting of cross-slot pipelines with a static slot map.
package rediscluster

import (
	"context"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/testing/redisslot"
	"github.com/redis/go-redis/v9"
)

// SlotSplit is the first slot served by the high node.
const SlotSplit = 8192

// TwoNode is a Redis Cluster client whose slot range is split between two miniredis servers.
type TwoNode struct {
	Low     *miniredis.Miniredis
	High    *miniredis.Miniredis
	Cluster *redis.ClusterClient
}

// NewTwoNode starts two miniredis servers and a cluster client with a static slot map.
func NewTwoNode(t testing.TB) *TwoNode {
	t.Helper()

	low := miniredis.RunT(t)
	high := miniredis.RunT(t)

	cluster := redis.NewClusterClient(&redis.ClusterOptions{
		ClusterSlots: func(context.Context) ([]redis.ClusterSlot, error) {
			return []redis.ClusterSlot{
				{Start: 0, End: SlotSplit - 1, Nodes: []redis.ClusterNode{{Addr: low.Addr()}}},
				{Start: SlotSplit, End: 16383, Nodes: []redis.ClusterNode{{Addr: high.Addr()}}},
			}, nil
		},
	})

	t.Cleanup(func() { _ = cluster.Close() })

	return &TwoNode{Low: low, High: high, Cluster: cluster}
}

// Node returns the miniredis server that owns key.
func (c *TwoNode) Node(key string) *miniredis.Miniredis {
	if IsHigh(key) {
		return c.High
	}

	return c.Low
}

// IsHigh reports whether the high node owns key.
func IsHigh(key string) bool {
	return redisslot.Slot(key) >= SlotSplit
}

// KeyOnNode returns a key named after base whose slot is served by the low or the high node.
func KeyOnNode(t testing.TB, base string, high bool) string {
	t.Helper()

	for index := range 1000 {
		key := fmt.Sprintf("%s-%d", base, index)
		if IsHigh(key) == high {
			return key
		}
	}

	t.Fatalf("no key for base %q on the requested node", base)

	return ""
}
