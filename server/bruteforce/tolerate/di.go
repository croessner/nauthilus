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

package tolerate

import (
	"sync/atomic"

	"github.com/croessner/nauthilus/server/rediscli"
)

// Redis DI seam for bruteforce tolerations.
//
// The tolerate subsystem historically accessed Redis via the global singleton.
// To migrate consumers without a large signature refactor, we keep a package-level
// default client that is set at boundaries from the injected `redifx.Client`.

type clientHolder struct {
	client rediscli.Client
}

var defaultClient atomic.Value

func init() {
	defaultClient.Store(clientHolder{client: nil})
}

// SetDefaultClient sets the tolerate-wide default Redis client.
func SetDefaultClient(client rediscli.Client) {
	defaultClient.Store(clientHolder{client: client})
}
