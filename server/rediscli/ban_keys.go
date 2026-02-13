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

	"github.com/croessner/nauthilus/server/definitions"
)

// GetBruteForceBanKey returns the Redis key for an individual per-network ban.
// Format: prefix + "bf:ban:" + network (e.g. "nauthilus:bf:ban:192.168.1.0/24").
func GetBruteForceBanKey(prefix, network string) string {
	return prefix + definitions.RedisBruteForceBanPrefix + network
}

// GetBanIndexShard computes the ZSET shard index (0–15) for a given network string
// using CRC32 and masking the lowest nibble.
func GetBanIndexShard(network string) byte {
	return byte(crc32.ChecksumIEEE([]byte(network)) & 0x0F)
}

// GetBruteForceBanIndexShardKey returns the Redis key for one of the 16 ZSET ban-index shards.
// Format: prefix + "bf:{bans}:" + hex-nibble (e.g. "nauthilus:bf:{bans}:A").
// The hash-tag {bans} ensures all shards land on the same Redis Cluster slot.
func GetBruteForceBanIndexShardKey(prefix string, shard byte) string {
	return fmt.Sprintf("%s%s%X", prefix, definitions.RedisBruteForceBanIndexPrefix, shard)
}

// GetAllBruteForceBanIndexKeys returns all 16 ZSET shard keys for the ban index.
// This is used as the KEYS parameter for the Lua listing script.
func GetAllBruteForceBanIndexKeys(prefix string) []string {
	keys := make([]string, definitions.BanIndexShardCount)

	for i := range definitions.BanIndexShardCount {
		keys[i] = GetBruteForceBanIndexShardKey(prefix, byte(i))
	}

	return keys
}
