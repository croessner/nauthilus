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

package redisslot

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// NewGuardedMiniredis starts a test-owned miniredis and returns a client whose multi-key operations are
// checked by a Guard, so tests fail on anything that would raise CROSSSLOT in Redis Cluster.
func NewGuardedMiniredis(t *testing.T, keyPrefix string) (*miniredis.Miniredis, *redis.Client, *Guard) {
	t.Helper()

	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	guard := NewGuard(t, keyPrefix).Attach(client)

	t.Cleanup(func() { _ = client.Close() })

	return server, client, guard
}
