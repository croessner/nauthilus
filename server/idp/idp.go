// Copyright (C) 2025 Christian Rößner
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
	"github.com/croessner/nauthilus/server/backend"
	"github.com/gin-gonic/gin"
)

// IdentityProvider defines the interface for our internal IdP services.
type IdentityProvider interface {
	// Authenticate performs user authentication using Nauthilus core logic.
	Authenticate(ctx *gin.Context, username, password string, oidcCID string, samlEntityID string) (*backend.User, error)

	// GetUserByUsername retrieves user details and attributes without performing password authentication.
	GetUserByUsername(ctx *gin.Context, username string, oidcCID string, samlEntityID string) (*backend.User, error)

	// GetClaims retrieves user attributes and maps them to OIDC/SAML claims for a specific client.
	GetClaims(user *backend.User, client any) (map[string]any, error)

	// IsDelayedResponse returns true if delayed response is enabled for the given client.
	IsDelayedResponse(clientID string, samlEntityID string) bool
}
