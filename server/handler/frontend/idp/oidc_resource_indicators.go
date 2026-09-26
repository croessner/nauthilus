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
	"strings"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/idp"
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

// acceptTokenResourceNarrowing checks, before a grant is consumed, that the token request only narrows
// the granted resources. It answers invalid_target otherwise.
func acceptTokenResourceNarrowing(ctx *gin.Context, granted []string) bool {
	if _, err := idp.NarrowAccessTokenResources(granted, oidcRequestedResources(ctx)); err != nil {
		writeOIDCInvalidTargetResponse(ctx)

		return false
	}

	return true
}

// joinResources renders validated resources for space-separated flow metadata.
func joinResources(resources []string) string {
	return strings.Join(resources, " ")
}
