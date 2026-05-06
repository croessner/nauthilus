// Copyright (C) 2024-2025 Christian Rößner
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

package auth

import (
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/environment"
	"github.com/gin-gonic/gin"
)

// DefaultEnvironmentEngine evaluates Lua environment sources for the pre-auth stage.
//
//goland:nointerface
type DefaultEnvironmentEngine struct{}

// Evaluate runs configured Lua environment sources for the request.
func (DefaultEnvironmentEngine) Evaluate(ctx *gin.Context, view *core.StateView) (bool, bool, []any, *string, error) {
	auth := view.Auth()

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	defer lualib.PutCommonRequest(commonRequest)

	auth.FillCommonRequest(commonRequest)

	environmentRequest := environment.Request{
		Logs:               nil,
		Context:            auth.Runtime.Context,
		HTTPClientContext:  auth.Request.HTTPClientContext,
		HTTPClientRequest:  auth.Request.HTTPClientRequest,
		Authenticated:      auth.Runtime.Authenticated,
		NoAuth:             auth.Request.NoAuth,
		BruteForceCounter:  0,
		MasterUserMode:     auth.Runtime.MasterUserMode,
		AdditionalFeatures: auth.Runtime.AdditionalFeatures,
		CommonRequest:      commonRequest,
	}

	triggered, abort, err := environmentRequest.CallEnvironmentLua(ctx, auth.Cfg(), auth.Logger(), auth.Redis())

	// Provide logs and status
	var logs []any
	if environmentRequest.Logs != nil {
		for i := range *environmentRequest.Logs {
			logs = append(logs, (*environmentRequest.Logs)[i])
		}
	}

	newStatus := environmentRequest.StatusMessage

	return triggered, abort, logs, newStatus, err
}
