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
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/gin-gonic/gin"
)

// DefaultFeatureEngine implements the Lua feature evaluation analogous to the previous AuthState.FeatureLua
// (excluding the localhost/whitelist shortcuts; those remain in the orchestrator in core/features.go).
//
//goland:nointerface
type DefaultFeatureEngine struct{}

func (DefaultFeatureEngine) Evaluate(ctx *gin.Context, view *core.StateView) (bool, bool, []any, *string, error) {
	auth := view.Auth()

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()
	auth.FillCommonRequest(commonRequest)

	featReq := feature.Request{
		Logs:               nil,
		Context:            auth.Context,
		HTTPClientContext:  auth.HTTPClientContext,
		HTTPClientRequest:  auth.HTTPClientRequest,
		NoAuth:             auth.NoAuth,
		BruteForceCounter:  0,
		MasterUserMode:     auth.MasterUserMode,
		PasswordHistory:    auth.PasswordHistory,
		AdditionalFeatures: auth.AdditionalFeatures,
		CommonRequest:      commonRequest,
	}

	triggered, abort, err := featReq.CallFeatureLua(ctx, auth.Cfg(), auth.Logger(), auth.Redis())

	// Provide logs and status
	var logs []any
	if featReq.Logs != nil {
		for i := range *featReq.Logs {
			logs = append(logs, (*featReq.Logs)[i])
		}
	}

	newStatus := featReq.StatusMessage

	lualib.PutCommonRequest(commonRequest)

	return triggered, abort, logs, newStatus, err
}
