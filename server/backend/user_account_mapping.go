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

package backend

import (
	"context"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
)

// SetUserAccountMapping writes/updates the username → account mapping in Redis.
//
// Core packages should not call `rediscli.GetClient()` directly.
// This helper uses the backend Redis seam (`getDefaultRedisClient()`).
func SetUserAccountMapping(ctx context.Context, username, account string) error {
	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserHashKey

	return getDefaultRedisClient().GetWriteHandle().HSet(ctx, key, username, account).Err()
}
