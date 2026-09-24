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

package health

import (
	"log/slog"
	"net/http"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/gin-gonic/gin"
)

// LivenessPath is the route of the liveness probe.
const LivenessPath = "/livez"

// livenessContentType is the media type of the fixed liveness document.
const livenessContentType = "application/json; charset=utf-8"

// livenessBody is the fixed liveness document. It carries the "status" field of HealthzResult with the
// value "up", so every client that understands the readiness answer of /healthz, including the image's
// healthcheck binary, accepts it. It is preallocated because the probe must stay cheap under load.
var livenessBody = []byte(`{"status":"` + healthzStatusUp + `"}`)

// LivenessCheck answers the liveness probe. It reports only that the HTTP server still serves requests
// and deliberately checks no dependency (Redis, LDAP, backends): a slow or failing dependency makes an
// instance unready through /healthz, but it is no reason to restart the process.
func LivenessCheck(ctx *gin.Context, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	_ = level.Debug(logger).Log(definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey), definitions.LogKeyMsg, "Liveness check")

	ctx.Data(http.StatusOK, livenessContentType, livenessBody)
}
