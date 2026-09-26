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
	"net/http"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/gin-gonic/gin"
)

// writeOIDCInvalidTargetResponse answers a rejected RFC 8707 resource parameter.
func writeOIDCInvalidTargetResponse(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidTarget})
}

// oidcRequestedResources returns every resource parameter of the request. The parameter is
// multi-valued (RFC 8707), so it never takes part in the duplicate-parameter rejection.
func oidcRequestedResources(ctx *gin.Context) []string {
	return oidcRequestValues(ctx, oidcParamResource)
}

// validateRequestedResources checks the resources an issuing client asks for at authorization time.
func (h *OIDCHandler) validateRequestedResources(client *config.OIDCClient, requested []string) ([]string, error) {
	return h.idp.ResourceRegistry().ValidateRequestedResources(client, requested)
}

// acceptTokenResources checks, before a grant is consumed, that the token request only narrows the
// granted resources and that the client may still obtain them. It answers invalid_target otherwise.
func (h *OIDCHandler) acceptTokenResources(ctx *gin.Context, client *config.OIDCClient, granted []string) bool {
	if err := h.idp.CheckAccessTokenResources(client, granted, oidcRequestedResources(ctx)); err != nil {
		writeOIDCInvalidTargetResponse(ctx)

		return false
	}

	return true
}

// precheckAuthorizationCodeResources rejects an invalid resource narrowing before the authorization code is
// consumed. It only reads the code; single use stays with the atomic consume, which also decides every code
// that cannot be read here or belongs to another client.
func (h *OIDCHandler) precheckAuthorizationCodeResources(ctx *gin.Context, client *config.OIDCClient, code string) bool {
	if len(oidcRequestedResources(ctx)) == 0 {
		return true
	}

	session, err := h.storage.GetSession(ctx.Request.Context(), code)
	if err != nil || session == nil || session.ClientID != client.ClientID {
		return true
	}

	return h.acceptTokenResources(ctx, client, session.AccessTokenResources)
}
