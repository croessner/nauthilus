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

package deps

import (
	"github.com/gin-gonic/gin"
	kitlog "github.com/go-kit/log"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
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
type DefaultServices struct{}

func NewDefaultServices() *DefaultServices {
	return &DefaultServices{}
}

// Hydra/Login

// LoginGETHandler handles GET requests for the login page, performing login flow initiation and error handling.
func (DefaultServices) LoginGETHandler() gin.HandlerFunc {
	return core.LoginGETHandler
}

// LoginPOSTHandler handles POST requests for the login page, managing the login flow, validation, and 2FA logic.
func (DefaultServices) LoginPOSTHandler() gin.HandlerFunc {
	return core.LoginPOSTHandler
}

// Device/U2F/FIDO2 login

// DeviceGETHandler processes GET requests for the device login page, handling login challenges, CSRF tokens, and UI rendering.
func (DefaultServices) DeviceGETHandler() gin.HandlerFunc {
	return core.DeviceGETHandler
}

// DevicePOSTHandler handles POST requests for the device authentication page.
// It processes device-related login data and manages error handling for unsupported functionality.
func (DefaultServices) DevicePOSTHandler() gin.HandlerFunc {
	return core.DevicePOSTHandler
}

// Consent

// ConsentGETHandler processes GET requests to the '/consent' page, handling consent challenges, CSRF tokens, and error cases.
func (DefaultServices) ConsentGETHandler() gin.HandlerFunc {
	return core.ConsentGETHandler
}

// ConsentPOSTHandler handles POST requests to the '/consent' endpoint, processing consent challenges and handling errors.
func (DefaultServices) ConsentPOSTHandler() gin.HandlerFunc {
	return core.ConsentPOSTHandler
}

// Logout

// LogoutGETHandler handles GET requests to the '/logout' page, managing logout challenges, session checks, and redirects.
func (DefaultServices) LogoutGETHandler() gin.HandlerFunc {
	return core.LogoutGETHandler
}

// LogoutPOSTHandler handles POST requests to the '/logout/post' endpoint, managing logout challenges and handling errors.
func (DefaultServices) LogoutPOSTHandler() gin.HandlerFunc {
	return core.LogoutPOSTHandler
}

// Notify

// NotifyGETHandler handles GET requests for the notification page, managing HTTP status, messages, and HTML rendering.
func (DefaultServices) NotifyGETHandler() gin.HandlerFunc {
	return core.NotifyGETHandler
}

// Two-Factor (2FA)

// LoginGET2FAHandler handles GET requests for the 2FA registration page, managing session state and TOTP page display logic.
func (DefaultServices) LoginGET2FAHandler() gin.HandlerFunc {
	return core.LoginGET2FAHandler
}

// LoginPOST2FAHandler handles POST requests for the '/2fa/v1/register/post' endpoint, managing TOTP-based 2FA processing.
func (DefaultServices) LoginPOST2FAHandler() gin.HandlerFunc {
	return core.LoginPOST2FAHandler
}

// Register2FAHomeHandler serves as the handler for the '/2fa/v1/register/home' endpoint, managing TOTP and WebAuthn setups.
func (DefaultServices) Register2FAHomeHandler() gin.HandlerFunc {
	return core.Register2FAHomeHandler
}

// RegisterTotpGETHandler serves the TOTP registration page, handles session validation and CSRF protection.
func (DefaultServices) RegisterTotpGETHandler() gin.HandlerFunc {
	return core.RegisterTotpGETHandler
}

// RegisterTotpPOSTHandler handles POST requests for TOTP registration, validates the TOTP code, and completes the registration.
func (DefaultServices) RegisterTotpPOSTHandler() gin.HandlerFunc {
	return core.RegisterTotpPOSTHandler
}

// WebAuthn

// BeginRegistration handles the initiation of WebAuthn registration, verifying user sessions and returning registration options.
func (DefaultServices) BeginRegistration() gin.HandlerFunc {
	return core.BeginRegistration
}

// FinishRegistration handles the completion of WebAuthn registration by verifying user session data and creating credentials.
func (DefaultServices) FinishRegistration() gin.HandlerFunc {
	return core.FinishRegistration
}

// Deps aggregates top-level dependencies to be injected into handler modules.
// Keep it minimal initially to avoid large refactors while enabling future DI.
type Deps struct {
	Cfg      config.File
	Logger   kitlog.Logger
	WebAuthn *webauthn.WebAuthn
	Svc      Services
}
