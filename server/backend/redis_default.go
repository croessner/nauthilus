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
	"sync/atomic"

	"github.com/croessner/nauthilus/server/rediscli"
)

// Backend Redis DI seam.
//
// The backend package historically accessed Redis via the global singleton.
// To migrate consumers without a massive signature refactor, we keep a package-level
// default client that can be set at boundaries from the injected `redifx.Client`.

type redisHolder struct {
	c rediscli.Client
}

var defaultRedis atomic.Value

func init() {
	defaultRedis.Store(redisHolder{c: nil})
}

// SetDefaultRedisClient sets the backend-wide default Redis client.
func SetDefaultRedisClient(c rediscli.Client) {
	defaultRedis.Store(redisHolder{c: c})
}
