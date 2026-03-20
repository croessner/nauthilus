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

package adminui

import (
	"errors"

	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/middleware/oidcbearer"
	"github.com/gin-gonic/gin"
)

// Setup registers admin UI routes if enabled in configuration.
func Setup(router *gin.Engine, deps *handlerdeps.Deps) error {
	if deps == nil || deps.Cfg == nil {
		return errors.New("adminui setup requires non-nil deps (Cfg)")
	}

	adminUI := deps.Cfg.GetServer().GetAdminUI()
	if !adminUI.IsEnabled() {
		return nil
	}

	if !deps.Cfg.GetServer().GetFrontend().IsEnabled() {
		return errors.New("adminui requires server.frontend.enabled=true")
	}

	authMode := AuthMode(adminUI.GetAuthMode())
	apiOIDCEnabled := adminUI.GetAPIOIDC().Enabled

	var validator oidcbearer.TokenValidator
	if apiOIDCEnabled && deps.Cfg.GetServer().GetOIDCAuth().IsEnabled() {
		validator = idp.NewNauthilusIdP(deps)
	}

	New(deps, authMode, apiOIDCEnabled, validator, nil, nil, nil).Register(router)

	return nil
}
