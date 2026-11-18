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
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// authorizationServerMetadataPath is the RFC 8414 well-known suffix for authorization server metadata.
	authorizationServerMetadataPath = "/.well-known/oauth-authorization-server"

	// authorizationServerMetadataIssuerPathParam carries the issuer path of the RFC 8414 path-insertion form.
	authorizationServerMetadataIssuerPathParam = "issuerPath"
)

// AuthorizationServerMetadata serves RFC 8414 authorization server metadata. The root form is always served (it is
// also what a reverse proxy forwards for the appended form below an issuer path). The path-insertion form
// "/.well-known/oauth-authorization-server/<issuer path>" is served only for the path of the current issuer, so the
// route stays correct across issuer reloads and never answers for a foreign issuer.
func (h *OIDCHandler) AuthorizationServerMetadata(ctx *gin.Context) {
	issuerPath := ctx.Param(authorizationServerMetadataIssuerPathParam)
	if issuerPath != "" && issuerPath != configuredIssuerPath(h.deps.Cfg.GetIDP().OIDC.Issuer) {
		ctx.Status(http.StatusNotFound)

		return
	}

	ctx.JSON(http.StatusOK, h.providerMetadata())
}

// configuredIssuerPath returns the path component of the issuer without a trailing slash, or "" for an issuer
// without a path or an unparsable issuer. An empty result never matches a path-insertion request.
func configuredIssuerPath(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return ""
	}

	return strings.TrimRight(parsed.Path, "/")
}
