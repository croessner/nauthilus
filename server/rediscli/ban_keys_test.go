// Copyright (C) 2024 Christian Rößner
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

package rediscli

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/stretchr/testify/assert"
)

type banKeyCase[T any] struct {
	name     string
	prefix   string
	input    T
	expected string
}

// runBanKeyCases verifies prefix-sensitive ban-key builders.
func runBanKeyCases[T any](t *testing.T, tests []banKeyCase[T], build func(string, T) string) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := build(tt.prefix, tt.input)

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetBruteForceBanKey(t *testing.T) {
	tests := []banKeyCase[string]{
		{
			name:     "IPv4 network with prefix",
			prefix:   "nauthilus:",
			input:    "192.168.1.0/24",
			expected: "nauthilus:bf:ban:192.168.1.0/24",
		},
		{
			name:     "IPv6 network with prefix",
			prefix:   "nauthilus:",
			input:    "2001:db8::/32",
			expected: "nauthilus:bf:ban:2001:db8::/32",
		},
		{
			name:     "empty prefix",
			prefix:   "",
			input:    "10.0.0.0/8",
			expected: "bf:ban:10.0.0.0/8",
		},
	}

	runBanKeyCases(t, tests, GetBruteForceBanKey)
}

func TestGetBruteForceBanKeyPattern(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		expected string
	}{
		{
			name:     "prefix with namespace",
			prefix:   "nauthilus:",
			expected: "nauthilus:bf:ban:*",
		},
		{
			name:     "empty prefix",
			prefix:   "",
			expected: "bf:ban:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetBruteForceBanKeyPattern(tt.prefix)

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseBruteForceBanKey(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		key      string
		expected string
		ok       bool
	}{
		{
			name:     "valid key with prefix",
			prefix:   "nauthilus:",
			key:      "nauthilus:bf:ban:192.168.1.0/24",
			expected: "192.168.1.0/24",
			ok:       true,
		},
		{
			name:     "valid key without prefix",
			prefix:   "",
			key:      "bf:ban:2001:db8::/32",
			expected: "2001:db8::/32",
			ok:       true,
		},
		{
			name:     "invalid prefix",
			prefix:   "nauthilus:",
			key:      "other:bf:ban:10.0.0.0/8",
			expected: "",
			ok:       false,
		},
		{
			name:     "missing network",
			prefix:   "nauthilus:",
			key:      "nauthilus:bf:ban:",
			expected: "",
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseBruteForceBanKey(tt.prefix, tt.key)

			assert.Equal(t, tt.expected, result)
			assert.Equal(t, tt.ok, ok)
		})
	}
}

func TestGetBanIndexShard(t *testing.T) {
	tests := []struct {
		name    string
		network string
	}{
		{name: "IPv4 /24", network: "192.168.1.0/24"},
		{name: "IPv4 /32", network: "10.0.0.1/32"},
		{name: "IPv6 /64", network: "2001:db8::/64"},
		{name: "IPv6 /128", network: "::1/128"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shard := GetBanIndexShard(tt.network)

			assert.Less(t, shard, byte(definitions.BanIndexShardCount), "shard must be in range 0-15")
		})
	}

	// Verify deterministic: same input always yields the same shard.
	shard1 := GetBanIndexShard("192.168.1.0/24")
	shard2 := GetBanIndexShard("192.168.1.0/24")

	assert.Equal(t, shard1, shard2, "same input must produce same shard")

	// Verify distribution: different inputs should not all map to the same shard.
	shardSet := make(map[byte]bool)
	networks := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"192.168.1.0/24", "192.168.2.0/24", "10.1.0.0/16",
		"2001:db8::/32", "2001:db8:1::/48", "fd00::/8",
	}

	for _, n := range networks {
		shardSet[GetBanIndexShard(n)] = true
	}

	assert.Greater(t, len(shardSet), 1, "different networks should map to multiple shards")
}

func TestGetBruteForceBanIndexShardKey(t *testing.T) {
	tests := []banKeyCase[byte]{
		{
			name:     "shard 0",
			prefix:   "nauthilus:",
			input:    0,
			expected: "nauthilus:bf:bans:0",
		},
		{
			name:     "shard 15 (F)",
			prefix:   "nauthilus:",
			input:    15,
			expected: "nauthilus:bf:bans:F",
		},
		{
			name:     "shard 10 (A)",
			prefix:   "test:",
			input:    10,
			expected: "test:bf:bans:A",
		},
	}

	runBanKeyCases(t, tests, GetBruteForceBanIndexShardKey)
}

func TestGetAllBruteForceBanIndexKeys(t *testing.T) {
	prefix := "nauthilus:"
	keys := GetAllBruteForceBanIndexKeys(prefix)

	assert.Len(t, keys, definitions.BanIndexShardCount)

	for i, key := range keys {
		expected := GetBruteForceBanIndexShardKey(prefix, byte(i))

		assert.Equal(t, expected, key, "key at index %d", i)
	}

	// Verify first and last key explicitly.
	assert.Equal(t, "nauthilus:bf:bans:0", keys[0])
	assert.Equal(t, "nauthilus:bf:bans:F", keys[15])
}
