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

//go:build hydra
// +build hydra

package deps

import (
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/rediscli"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Services defines the transport-agnostic business endpoints that HTTP handlers
// depend on. Each method returns a gin.HandlerFunc to keep registration code
// unchanged while allowing a clean DI seam.
type Services interface {
	// Hydra/Login

	// LoginGETHandler returns a gin.HandlerFunc responsible for rendering the login page.
	LoginGETHandler() gin.HandlerFunc

	// LoginPOSTHandler returns a gin.HandlerFunc to handle POST requests for login, performing authentication and session creation.
	LoginPOSTHandler() gin.HandlerFunc

	// Device/U2F/FIDO2 login

	// DeviceGETHandler returns a gin.HandlerFunc to handle GET requests for the device login page, supporting U2F/FIDO2 workflows.
	DeviceGETHandler() gin.HandlerFunc

	// DevicePOSTHandler handles POST requests for the device login process, supporting U2F/FIDO2 workflows for authentication.
	DevicePOSTHandler() gin.HandlerFunc

	// Consent

	// ConsentGETHandler handles GET requests for the consent page, retrieving necessary data for user consent processing.
	ConsentGETHandler() gin.HandlerFunc

	// ConsentPOSTHandler handles POST requests for the consent endpoint to process user consent and authorization decisions.
	ConsentPOSTHandler() gin.HandlerFunc

	// Logout

	// LogoutGETHandler provides a gin.HandlerFunc to handle GET requests for logging out, typically clearing sessions.
	LogoutGETHandler() gin.HandlerFunc

	// LogoutPOSTHandler handles POST requests for user logout, processing any required actions like session termination.
	LogoutPOSTHandler() gin.HandlerFunc

	// Notify

	// NotifyGETHandler returns a gin.HandlerFunc for handling GET requests on the notification endpoint.
	NotifyGETHandler() gin.HandlerFunc

	// Two-Factor (2FA)

	// LoginGET2FAHandler handles GET requests for the two-factor authentication login page.
	LoginGET2FAHandler() gin.HandlerFunc

	// LoginPOST2FAHandler handles POST requests for two-factor authentication during user login flow.
	LoginPOST2FAHandler() gin.HandlerFunc

	// Register2FAHomeHandler returns a handler for rendering the home page of the two-factor authentication registration process.
	Register2FAHomeHandler() gin.HandlerFunc

	// RegisterTotpGETHandler defines a handler that serves the GET request for TOTP registration.
	RegisterTotpGETHandler() gin.HandlerFunc

	// RegisterTotpPOSTHandler handles the POST request for registering a TOTP (Time-based One-Time Password) authenticator.
	RegisterTotpPOSTHandler() gin.HandlerFunc

	// WebAuthn

	// BeginRegistration initiates a new user registration process and returns a gin.HandlerFunc for handling HTTP requests.
	BeginRegistration() gin.HandlerFunc

	// FinishRegistration handles the final step of the registration process for a new user or device in the system.
	FinishRegistration() gin.HandlerFunc
}

// DefaultServices is the default implementation that delegates to core package handlers.
type DefaultServices struct {
	deps *Deps
}

// NewDefaultServices constructs the default Services implementation
// that delegates handler functions to the core package.
func NewDefaultServices(deps *Deps) *DefaultServices {
	return &DefaultServices{deps: deps}
}

// Hydra/Login

// LoginGETHandler handles GET requests for the login page, performing login flow initiation and error handling.
func (s *DefaultServices) LoginGETHandler() gin.HandlerFunc {
	return core.LoginGETHandler(s.deps)
}

// LoginPOSTHandler handles POST requests for the login page, managing the login flow, validation, and 2FA logic.
func (s *DefaultServices) LoginPOSTHandler() gin.HandlerFunc {
	return core.LoginPOSTHandler(s.deps)
}

// Device/U2F/FIDO2 login

// DeviceGETHandler processes GET requests for the device login page, handling login challenges, CSRF tokens, and UI rendering.
func (s *DefaultServices) DeviceGETHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := core.NewHydraHandlers(core.AuthDeps{
			Cfg:    s.deps.Cfg,
			Logger: s.deps.Logger,
			Env:    s.deps.Env,
			Redis:  s.deps.Redis,
		})
		h.DeviceGETHandler(ctx)
	}
}

// DevicePOSTHandler handles POST requests for the device authentication page.
// It processes device-related login data and manages error handling for unsupported functionality.
func (s *DefaultServices) DevicePOSTHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := core.NewHydraHandlers(core.AuthDeps{
			Cfg:    s.deps.Cfg,
			Logger: s.deps.Logger,
			Env:    s.deps.Env,
			Redis:  s.deps.Redis,
		})
		h.DevicePOSTHandler(ctx)
	}
}

// Consent

// ConsentGETHandler processes GET requests to the '/consent' page, handling consent challenges, CSRF tokens, and error cases.
func (s *DefaultServices) ConsentGETHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := core.NewHydraHandlers(core.AuthDeps{
			Cfg:    s.deps.Cfg,
			Logger: s.deps.Logger,
			Env:    s.deps.Env,
			Redis:  s.deps.Redis,
		})
		h.ConsentGETHandler(ctx)
	}
}

// ConsentPOSTHandler handles POST requests to the '/consent' endpoint, processing consent challenges and handling errors.
func (s *DefaultServices) ConsentPOSTHandler() gin.HandlerFunc {
	return core.ConsentPOSTHandler(s.deps)
}

// Logout

// LogoutGETHandler handles GET requests to the '/logout' page, managing logout challenges, session checks, and redirects.
func (s *DefaultServices) LogoutGETHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := core.NewHydraHandlers(core.AuthDeps{
			Cfg:    s.deps.Cfg,
			Logger: s.deps.Logger,
			Env:    s.deps.Env,
			Redis:  s.deps.Redis,
		})
		h.LogoutGETHandler(ctx)
	}
}

// LogoutPOSTHandler handles POST requests to the '/logout/post' endpoint, managing logout challenges and handling errors.
func (s *DefaultServices) LogoutPOSTHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := core.NewHydraHandlers(core.AuthDeps{
			Cfg:    s.deps.Cfg,
			Logger: s.deps.Logger,
			Env:    s.deps.Env,
			Redis:  s.deps.Redis,
		})
		h.LogoutPOSTHandler(ctx)
	}
}

// Notify

// NotifyGETHandler handles GET requests for the notification page, managing HTTP status, messages, and HTML rendering.
func (s *DefaultServices) NotifyGETHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := core.NewHydraHandlers(core.AuthDeps{
			Cfg:    s.deps.Cfg,
			Logger: s.deps.Logger,
			Env:    s.deps.Env,
			Redis:  s.deps.Redis,
		})
		h.NotifyGETHandler(ctx)
	}
}

// Two-Factor (2FA)

// LoginGET2FAHandler handles GET requests for the 2FA registration page, managing session state and TOTP page display logic.
func (s *DefaultServices) LoginGET2FAHandler() gin.HandlerFunc {
	return core.LoginGET2FAHandler(s.deps)
}

// LoginPOST2FAHandler handles POST requests for the '/2fa/v1/register/post' endpoint, managing TOTP-based 2FA processing.
func (s *DefaultServices) LoginPOST2FAHandler() gin.HandlerFunc {
	return core.LoginPOST2FAHandler(s.deps)
}

// Register2FAHomeHandler serves as the handler for the '/2fa/v1/register/home' endpoint, managing TOTP and WebAuthn setups.
func (s *DefaultServices) Register2FAHomeHandler() gin.HandlerFunc {
	return core.Register2FAHomeHandler(s.deps)
}

// RegisterTotpGETHandler serves the TOTP registration page, handles session validation and CSRF protection.
func (s *DefaultServices) RegisterTotpGETHandler() gin.HandlerFunc {
	return core.RegisterTotpGETHandler(s.deps)
}

// RegisterTotpPOSTHandler handles POST requests for TOTP registration, validates the TOTP code, and completes the registration.
func (s *DefaultServices) RegisterTotpPOSTHandler() gin.HandlerFunc {
	return core.RegisterTotpPOSTHandler(s.deps)
}

// WebAuthn

// BeginRegistration handles the initiation of WebAuthn registration, verifying user sessions and returning registration options.
func (s *DefaultServices) BeginRegistration() gin.HandlerFunc {
	return core.BeginRegistration(s.deps)
}

// FinishRegistration handles the completion of WebAuthn registration by verifying user session data and creating credentials.
func (s *DefaultServices) FinishRegistration() gin.HandlerFunc {
	return core.FinishRegistration(s.deps)
}

// Deps aggregates top-level dependencies to be injected into handler modules.
// Keep it minimal initially to avoid large refactors while enabling future DI.
type Deps struct {
	Cfg      config.File
	Env      config.Environment
	Logger   *slog.Logger
	Redis    rediscli.Client
	WebAuthn *webauthn.WebAuthn
	Svc      Services
}
