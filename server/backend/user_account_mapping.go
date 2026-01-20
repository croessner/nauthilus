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

	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/rediscli"
)

// SetUserAccountMapping writes/updates the username → account mapping in Redis.
func SetUserAccountMapping(ctx context.Context, cfg config.File, redisClient rediscli.Client, username, protocol, oidcClientID, account string) error {
	key := rediscli.GetUserHashKey(cfg.GetServer().GetRedis().GetPrefix(), username)

	field := accountcache.GetAccountMappingField(username, protocol, oidcClientID)

	return redisClient.GetWriteHandle().HSet(ctx, key, field, account).Err()
}
