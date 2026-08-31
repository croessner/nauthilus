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

// Package deps provides deps functionality.
package deps

import (
	"log/slog"

	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	coreauth "github.com/croessner/nauthilus/v4/server/core/auth"
	"github.com/croessner/nauthilus/v4/server/core/language"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/handler/policyhttp"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/rediscli"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Services defines the transport-agnostic business endpoints that HTTP handlers
// depend on. Each method returns a gin.HandlerFunc to keep registration code
// unchanged while allowing a clean DI seam.
type Services any

// DefaultServices is the default implementation that delegates to core package handlers.
type DefaultServices struct {
	deps *Deps
}

// NewDefaultServices constructs the default Services implementation
// that delegates handler functions to the core package.
func NewDefaultServices(deps *Deps) *DefaultServices {
	return &DefaultServices{deps: deps}
}

// Auth provides the exported Auth method.
func (d *Deps) Auth() core.AuthDeps {
	cfg := d.Cfg
	if d.CfgProvider != nil {
		cfg = d.CfgProvider.Current().File
	}

	hostServices := d.HostServices
	if !hostServices.Valid() {
		hostServices = coreauth.NewDefaultHostServices()
	}

	return core.AuthDeps{
		Cfg:                  cfg,
		Env:                  d.Env,
		Logger:               d.Logger,
		Redis:                d.Redis,
		AccountCache:         d.AccountCache,
		Channel:              d.Channel,
		Tolerate:             d.Tolerate,
		PluginBackendFactory: pluginruntime.NewBackendManagerFactory(d.PluginRunner),
		NativeRuntime:        pluginruntime.NewAuthnRequestRuntime(),
		HostServices:         hostServices,
		LDAPQueue:            d.LDAPQueue,
		LDAPAuthQueue:        d.LDAPAuthQueue,
	}
}

// AuthPtr provides the exported AuthPtr method.
func (d *Deps) AuthPtr() *core.AuthDeps {
	auth := d.Auth()

	return &auth
}

// Deps aggregates top-level dependencies to be injected into handler modules.
// Keep it minimal initially to avoid large refactors while enabling future DI.
type Deps struct {
	Cfg          config.File
	CfgProvider  configfx.Provider
	Env          config.Environment
	Logger       *slog.Logger
	Redis        rediscli.Client
	WebAuthn     *webauthn.WebAuthn
	AccountCache *accountcache.Manager
	Channel      backend.Channel
	Svc          Services
	LangManager  language.Manager
	TokenFlusher core.TokenFlusher
	// AuthApplication is the shared authentication application boundary for backchannel and IdP transports.
	AuthApplication core.AuthApplicationService
	// MessageResolver resolves policy-selected status messages for IDP UI rendering.
	MessageResolver localization.MessageResolver
	// PolicyDecision is the admission-enforcing application authority for Policy transports.
	PolicyDecision decisionservice.PreparedService
	// PolicyTransport resolves trusted HTTP protection evidence for the Policy boundary.
	PolicyTransport policyhttp.TransportEvidence
	// PluginRunner is the explicit process-owned native hook and backend runtime.
	PluginRunner *pluginruntime.Runner
	// Tolerate is the explicit boot-lifetime brute-force tolerance owner.
	Tolerate tolerate.Tolerate
	// HostServices is the immutable host implementation bundle for authn requests.
	HostServices core.AuthnHostServices
	// LDAPQueue is the explicit process-owned LDAP lookup queue.
	LDAPQueue core.LDAPRequestQueue
	// LDAPAuthQueue is the explicit process-owned LDAP authentication queue.
	LDAPAuthQueue core.LDAPAuthRequestQueue
	// RouteArtifacts owns immutable listener, template, and public-file material prepared before startup commit.
	RouteArtifacts *core.RouteArtifacts
}
