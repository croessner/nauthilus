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
	"log/slog"
	"net/url"
	"strings"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

func (h *OIDCHandler) logIncomingOIDCFlowRequest(ctx *gin.Context, flow string, grantType string, clientID string) {
	if h == nil || h.deps == nil {
		return
	}

	logIncomingIDPFlowRequest(ctx, h.deps.Logger, "oidc", flow, clientID, "", grantType)
}

func (h *SAMLHandler) logIncomingSAMLFlowRequest(ctx *gin.Context, flow string, entityID string) {
	if h == nil || h.deps == nil {
		return
	}

	logIncomingIDPFlowRequest(ctx, h.deps.Logger, "saml", flow, "", entityID, "")
}

func logIncomingIDPFlowRequest(
	ctx *gin.Context,
	logger *slog.Logger,
	protocol string,
	flow string,
	clientID string,
	samlEntityID string,
	grantType string,
) {
	if ctx == nil || ctx.Request == nil {
		return
	}

	keyvals := []any{
		definitions.LogKeyGUID, util.WithNotAvailable(ctx.GetString(definitions.CtxGUIDKey)),
		definitions.LogKeyProtocol, util.WithNotAvailable(strings.TrimSpace(protocol)),
		definitions.LogKeyMethod, util.WithNotAvailable(strings.TrimSpace(ctx.Request.Method)),
		definitions.LogKeyUriPath, util.WithNotAvailable(strings.TrimSpace(ctx.Request.URL.Path)),
		"idp_flow", util.WithNotAvailable(strings.TrimSpace(flow)),
		definitions.LogKeyOIDCCID, util.WithNotAvailable(strings.TrimSpace(clientID)),
		definitions.LogKeySAMLEntityID, util.WithNotAvailable(strings.TrimSpace(samlEntityID)),
		definitions.LogKeyMsg, "Processing incoming request",
	}

	if strings.TrimSpace(grantType) != "" {
		keyvals = append(keyvals, "grant_type", grantType)
	}

	level.Notice(logger).WithContext(ctx).Log(keyvals...)
}

func oidcTokenRequestClientID(ctx *gin.Context) string {
	if ctx == nil || ctx.Request == nil {
		return ""
	}

	clientID := strings.TrimSpace(formValue(ctx, "client_id"))
	if clientID != "" {
		return clientID
	}

	headerClientID, _, ok := ctx.Request.BasicAuth()
	if !ok {
		return ""
	}

	unescapedClientID, err := url.QueryUnescape(headerClientID)
	if err != nil {
		return strings.TrimSpace(headerClientID)
	}

	return strings.TrimSpace(unescapedClientID)
}
