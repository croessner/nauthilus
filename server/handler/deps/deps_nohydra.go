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

package deps

import (
	"log/slog"
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/rediscli"

	"github.com/gin-gonic/gin"
)

// Services defines the transport-agnostic business endpoints that HTTP handlers
// depend on. Each method returns a gin.HandlerFunc to keep registration code
// unchanged while allowing a clean DI seam.
type Services interface {
	// LoginGETHandler returns a gin.HandlerFunc to handle GET requests for the login endpoint and display the login page.
	LoginGETHandler() gin.HandlerFunc

	// LoginPOSTHandler processes POST requests for user login, including authentication and session management logic.
	LoginPOSTHandler() gin.HandlerFunc

	// DeviceGETHandler returns a gin.HandlerFunc to handle GET requests for device-based login or authentication workflows.
	DeviceGETHandler() gin.HandlerFunc

	// DevicePOSTHandler processes POST requests for device-based login or authentication, handling validation and security logic.
	DevicePOSTHandler() gin.HandlerFunc

	// ConsentGETHandler returns a gin.HandlerFunc to handle GET requests for user consent, rendering the consent page or details.
	ConsentGETHandler() gin.HandlerFunc

	// ConsentPOSTHandler handles POST requests for the consent endpoint, managing user consent submissions in ongoing sessions.
	ConsentPOSTHandler() gin.HandlerFunc

	// LogoutGETHandler handles GET requests for user logout functionality, orchestrating necessary session termination processes.
	LogoutGETHandler() gin.HandlerFunc

	// LogoutPOSTHandler handles POST requests for user logout by terminating the active session and cleaning up related resources.
	LogoutPOSTHandler() gin.HandlerFunc

	// NotifyGETHandler provides a handler function for the Notify GET endpoint, commonly used for serving notifications.
	NotifyGETHandler() gin.HandlerFunc

	// LoginGET2FAHandler handles GET requests for initiating the two-factor authentication (2FA) login process.
	LoginGET2FAHandler() gin.HandlerFunc

	// LoginPOST2FAHandler handles the POST requests for Two-Factor Authentication during the login process.
	LoginPOST2FAHandler() gin.HandlerFunc

	// Register2FAHomeHandler handles the registration process for two-factor authentication home setup.
	Register2FAHomeHandler() gin.HandlerFunc

	// RegisterTotpGETHandler returns a gin.HandlerFunc for handling GET requests to initiate TOTP registration.
	RegisterTotpGETHandler() gin.HandlerFunc

	// RegisterTotpPOSTHandler handles HTTP POST requests for registering a TOTP device and returns a gin.HandlerFunc.
	RegisterTotpPOSTHandler() gin.HandlerFunc

	// BeginRegistration initializes the user registration process and returns a gin.HandlerFunc to handle the request.
	BeginRegistration() gin.HandlerFunc

	// FinishRegistration finalizes the registration process after the initial setup, validating and storing user details.
	FinishRegistration() gin.HandlerFunc
}

// DefaultServices is the default implementation that delegates to core package handlers.
// In non-hydra builds, hydra-related handlers are stubbed with 404 responses.
type DefaultServices struct {
	deps *Deps
}

// NewDefaultServices constructs the default Services implementation
// for non-hydra builds. All hydra-related handlers return 404 stubs.
func NewDefaultServices(deps *Deps) *DefaultServices { return &DefaultServices{deps: deps} }

// notFound returns a Gin handler that responds with HTTP 404 status and a "hydra disabled" message.
func notFound() gin.HandlerFunc {
	return func(c *gin.Context) { c.String(http.StatusNotFound, "hydra disabled") }
}

// LoginGETHandler returns a handler function that responds with a 404 status, indicating the login endpoint is disabled.
func (s *DefaultServices) LoginGETHandler() gin.HandlerFunc { return notFound() }

// LoginPOSTHandler returns a handler function that responds with a 404 status, indicating the login endpoint is disabled.
func (s *DefaultServices) LoginPOSTHandler() gin.HandlerFunc { return notFound() }

// DeviceGETHandler returns a handler function that responds with a 404 status, indicating the device endpoint is disabled.
func (s *DefaultServices) DeviceGETHandler() gin.HandlerFunc { return notFound() }

// DevicePOSTHandler returns a handler function that responds with a 404 status, indicating the device endpoint is disabled.
func (s *DefaultServices) DevicePOSTHandler() gin.HandlerFunc { return notFound() }

// ConsentGETHandler returns a handler function that responds with a 404 status, indicating the consent endpoint is disabled.
func (s *DefaultServices) ConsentGETHandler() gin.HandlerFunc { return notFound() }

// ConsentPOSTHandler returns a handler function that responds with a 404 status, indicating the consent endpoint is disabled.
func (s *DefaultServices) ConsentPOSTHandler() gin.HandlerFunc { return notFound() }

// LogoutGETHandler returns a handler function that responds with a 404 status, indicating the logout endpoint is disabled.
func (s *DefaultServices) LogoutGETHandler() gin.HandlerFunc { return notFound() }

// LogoutPOSTHandler returns a handler function that responds with a 404 status, indicating the logout endpoint is disabled.
func (s *DefaultServices) LogoutPOSTHandler() gin.HandlerFunc { return notFound() }

// NotifyGETHandler returns a handler function that delegates to the core.NotifyGETHandler for processing GET requests.
func (s *DefaultServices) NotifyGETHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		core.NotifyGETHandlerWithDeps(ctx, core.AuthDeps{
			Cfg:    s.deps.Cfg,
			Logger: s.deps.Logger,
			Env:    s.deps.Env,
			Redis:  s.deps.Redis,
		})
	}
}

// LoginGET2FAHandler returns a handler function that responds with a 404 status, indicating the 2FA login endpoint is disabled.
func (s *DefaultServices) LoginGET2FAHandler() gin.HandlerFunc { return notFound() }

// LoginPOST2FAHandler returns a handler function that responds with a 404 status, indicating the 2FA POST login endpoint is disabled.
func (s *DefaultServices) LoginPOST2FAHandler() gin.HandlerFunc { return notFound() }

// Register2FAHomeHandler returns a handler function that responds with a 404 status, indicating the 2FA home endpoint is disabled.
func (s *DefaultServices) Register2FAHomeHandler() gin.HandlerFunc { return notFound() }

// RegisterTotpGETHandler returns a handler function that responds with a 404 status, indicating the TOTP endpoint is disabled.
func (s *DefaultServices) RegisterTotpGETHandler() gin.HandlerFunc { return notFound() }

// RegisterTotpPOSTHandler returns a handler function that responds with a 404 status, indicating the TOTP POST endpoint is disabled.
func (s *DefaultServices) RegisterTotpPOSTHandler() gin.HandlerFunc { return notFound() }

// BeginRegistration returns a handler function that responds with a 404 status, indicating the registration endpoint is disabled.
func (s *DefaultServices) BeginRegistration() gin.HandlerFunc { return notFound() }

// FinishRegistration returns a handler function that responds with a 404 status, indicating the registration endpoint is disabled.
func (s *DefaultServices) FinishRegistration() gin.HandlerFunc { return notFound() }

// Deps aggregates top-level dependencies to be injected into handler modules.
// Keep it minimal initially to avoid large refactors while enabling future DI.
type Deps struct {
	Cfg    config.File
	Env    config.Environment
	Logger *slog.Logger
	Redis  rediscli.Client
	Svc    Services
}
