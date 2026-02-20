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
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
)

// handleClientCredentialsTokenExchange processes the client_credentials grant type
// within the token endpoint.
func (h *OIDCHandler) handleClientCredentialsTokenExchange(ctx *gin.Context, client *config.OIDCClient, grantType string) {
	clientID := client.ClientID

	if !client.SupportsGrantType("client_credentials") {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client"})

		return
	}

	requestedScopes := strings.Fields(formValue(ctx, "scope"))
	filteredScopes := h.idp.FilterScopes(client, requestedScopes)

	accessToken, expiresIn, err := h.idp.IssueClientCredentialsToken(ctx.Request.Context(), clientID, filteredScopes)
	if err != nil {
		h.logTokenError(ctx, grantType, clientID, err)

		return
	}

	h.sendTokenResponse(ctx, clientID, grantType, &tokenResponse{
		accessToken: accessToken,
		expiresIn:   expiresIn,
	})
}
