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

package idp

import (
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/middleware/oidcbearer"
	"github.com/golang-jwt/jwt/v5"
)

// canIntrospectAccessToken binds validated tokens to their recipient or an explicitly authorized backchannel inspector.
func canIntrospectAccessToken(client *config.OIDCClient, claims jwt.MapClaims) bool {
	if client == nil || client.Dynamic {
		return false
	}

	if oidcbearer.HasAudience(claims, client.ClientID) {
		return true
	}

	return client.AllowsBackchannelIntrospection() && oidcbearer.IsBackchannelAccessToken(claims)
}
