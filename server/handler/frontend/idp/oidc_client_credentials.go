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

	"github.com/croessner/nauthilus/v4/server/config"
	oidcserver "github.com/croessner/nauthilus/v4/server/idp"
	"github.com/gin-gonic/gin"
)

// handleClientCredentialsTokenExchange processes the client_credentials grant type
// within the token endpoint.
func (h *OIDCHandler) handleClientCredentialsTokenExchange(ctx *gin.Context, client *config.OIDCClient, grantType string) {
	clientID := client.ClientID

	if !client.SupportsGrantType(oidcGrantTypeClientCredentials) {
		ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorUnauthorizedClient})

		return
	}

	if client.IsPublicClient() {
		ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorUnauthorizedClient})

		return
	}

	requestedScopes := strings.Fields(formValue(ctx, "scope"))

	if !validateClientCredentialsTokenScopes(ctx, requestedScopes) {
		return
	}

	filteredScopes := h.idp.FilterScopes(client, requestedScopes)

	if !validateClientCredentialsTokenScopeTransition(ctx, requestedScopes, filteredScopes) {
		return
	}

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

// validateClientCredentialsTokenScopes rejects identity and mixed-resource scope sets.
func validateClientCredentialsTokenScopes(ctx *gin.Context, scopes []string) bool {
	return acceptClientCredentialsScopeValidation(ctx, oidcserver.ValidateClientCredentialsScopes(scopes))
}

// validateClientCredentialsTokenScopeTransition rejects resource-family changes introduced by client filtering.
func validateClientCredentialsTokenScopeTransition(ctx *gin.Context, requestedScopes []string, effectiveScopes []string) bool {
	return acceptClientCredentialsScopeValidation(
		ctx,
		oidcserver.ValidateClientCredentialsScopeTransition(requestedScopes, effectiveScopes),
	)
}

// acceptClientCredentialsScopeValidation maps one resource-classification result to the OAuth boundary.
func acceptClientCredentialsScopeValidation(ctx *gin.Context, err error) bool {
	if err == nil {
		return true
	}

	ctx.JSON(http.StatusBadRequest, gin.H{
		frontChannelLogoutTaskStatusError: oidcErrorInvalidScope,
		oidcJSONErrorDescriptionKey:       err.Error(),
	})

	return false
}
