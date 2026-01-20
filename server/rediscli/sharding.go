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

// GetShardID calculates a 2-digit hex shard ID (00-FF) for a given input string.
func GetShardID(input string) string {
	hash := crc32.ChecksumIEEE([]byte(input))
	return fmt.Sprintf("%02x", hash%256)
}

// GetUserHashKey returns the sharded Redis key for user account mapping.
func GetUserHashKey(prefix, username string) string {
	return fmt.Sprintf("%s%s:{%s}", prefix, definitions.RedisUserHashKey, GetShardID(username))
}

// GetBruteForceHashKey returns the sharded Redis key for brute-force tracking.
func GetBruteForceHashKey(prefix, network string) string {
	return fmt.Sprintf("%s%s:{%s}", prefix, definitions.RedisBruteForceHashKey, GetShardID(network))
}
