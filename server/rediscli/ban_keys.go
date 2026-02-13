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
	"fmt"
	"hash/crc32"
	"strings"

	"github.com/croessner/nauthilus/server/definitions"
)

// GetBruteForceBanKey returns the Redis key for an individual per-network ban.
// Format: prefix + "bf:ban:" + network (e.g. "nauthilus:bf:ban:192.168.1.0/24").
func GetBruteForceBanKey(prefix, network string) string {
	return prefix + definitions.RedisBruteForceBanPrefix + network
}

// GetBruteForceBanKeyPattern returns the Redis key pattern for all brute force ban keys.
func GetBruteForceBanKeyPattern(prefix string) string {
	return prefix + definitions.RedisBruteForceBanPrefix + "*"
}

// ParseBruteForceBanKey extracts the network part from a brute force ban key.
func ParseBruteForceBanKey(prefix, key string) (string, bool) {
	banPrefix := prefix + definitions.RedisBruteForceBanPrefix
	network, ok := strings.CutPrefix(key, banPrefix)
	if !ok || network == "" {
		return "", false
	}

	return network, true
}

// GetBanIndexShard computes the ZSET shard index (0–15) for a given network string
// using CRC32 and masking the lowest nibble.
func GetBanIndexShard(network string) byte {
	return byte(crc32.ChecksumIEEE([]byte(network)) & 0x0F)
}

// GetBruteForceBanIndexShardKey returns the Redis key for one of the 16 ZSET ban-index shards.
// Format: prefix + "bf:bans:" + hex-nibble (e.g. "nauthilus:bf:bans:A").
func GetBruteForceBanIndexShardKey(prefix string, shard byte) string {
	return fmt.Sprintf("%s%s%X", prefix, definitions.RedisBruteForceBanIndexPrefix, shard)
}

// GetAllBruteForceBanIndexKeys returns all 16 ZSET shard keys for the ban index.
func GetAllBruteForceBanIndexKeys(prefix string) []string {
	keys := make([]string, definitions.BanIndexShardCount)

	for i := range definitions.BanIndexShardCount {
		keys[i] = GetBruteForceBanIndexShardKey(prefix, byte(i))
	}

	return keys
}
