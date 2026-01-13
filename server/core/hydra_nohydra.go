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

//go:build !hydra
// +build !hydra

package core

import (
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
)

// WithLanguageMiddleware provides a no-op language middleware in non-hydra builds.
// It preserves the handler chain shape without introducing i18n or CSRF concerns here.
func WithLanguageMiddleware(_ AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) { ctx.Next() }
}

// InitHTTPClient is a no-op placeholder when building without the hydra tag.
// It maintains API parity with the hydra-enabled build where an HTTP client is initialized.
func InitHTTPClient(_ config.File) {}

// HandleErr renders a minimal error response when Hydra is disabled.
// It ensures core packages can signal errors uniformly across build variants.
func HandleErr(ctx *gin.Context, err error) {
	if err == nil {
		ctx.Status(http.StatusBadRequest)

		return
	}

	ctx.String(http.StatusBadRequest, err.Error())
}

// LoginGETHandler handles GET requests for the login endpoint, returning a 404 status if the service is disabled.
func LoginGETHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// LoginPOSTHandler handles POST requests to the login page, managing login flow, authentication validation, and optional 2FA logic.
func LoginPOSTHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// DeviceGETHandler handles GET requests for the device login page, currently returning a 404 Not Found indicating "hydra disabled".
func DeviceGETHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// DevicePOSTHandler handles POST requests for the device authentication page, returning a 404 response if disabled.
func DevicePOSTHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// ConsentGETHandler handles GET requests to the '/consent' endpoint, returning a not found status when Hydra is disabled.
func ConsentGETHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// ConsentPOSTHandler handles POST requests to the '/consent' endpoint, indicating that Hydra is disabled with a 404 response.
func ConsentPOSTHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// LogoutGETHandler manages GET requests to the '/logout' endpoint, returning a 404 status when the Hydra service is disabled.
func LogoutGETHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// LogoutPOSTHandler handles POST requests to the '/logout/post' endpoint, returning a 404 status when Hydra is disabled.
func LogoutPOSTHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// NotifyGETHandler handles GET requests for the notification page.
func NotifyGETHandler(ctx *gin.Context) {
	NotifyGETHandlerWithDeps(ctx, AuthDeps{
		Cfg:    getDefaultConfigFile(),
		Env:    getDefaultEnvironment(),
		Logger: getDefaultLogger(),
		Redis:  getDefaultRedisClient(),
	})
}

// LoginGET2FAHandler handles GET requests for the 2FA page, responding with a "hydra disabled" message when not enabled.
func LoginGET2FAHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// LoginPOST2FAHandler handles POST requests for 2FA registration, processing TOTP-based two-factor authentication logic.
func LoginPOST2FAHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// Register2FAHomeHandler serves the '/2fa/v1/register/home' endpoint, providing a response when 2FA features are unavailable.
func Register2FAHomeHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// RegisterTotpGETHandler serves the TOTP registration page and responds with a "hydra disabled" message if not enabled.
func RegisterTotpGETHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }

// RegisterTotpPOSTHandler handles POST requests for TOTP registration and returns a 404 status if the feature is disabled.
func RegisterTotpPOSTHandler(ctx *gin.Context) { ctx.String(http.StatusNotFound, "hydra disabled") }
