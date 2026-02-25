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
	"log/slog"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/core/language"
	"github.com/croessner/nauthilus/server/rediscli"

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

func (d *Deps) Auth() core.AuthDeps {
	return core.AuthDeps{
		Cfg:          d.Cfg,
		Env:          d.Env,
		Logger:       d.Logger,
		Redis:        d.Redis,
		AccountCache: d.AccountCache,
		Channel:      d.Channel,
	}
}

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
}
