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
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
)

type DefaultActionDispatcher struct{}

// Dispatch sends an action to the Lua execution pipeline, initializing context and preparing authentication details.
// It blocks until the action is completed and ensures proper resource cleanup.
func (DefaultActionDispatcher) Dispatch(view *core.StateView, featureName string, luaAction definitions.LuaAction) {
	auth := view.Auth()

	if !auth.Cfg().HaveLuaActions() {
		return
	}

	finished := make(chan action.Done)

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()
	auth.FillCommonRequest(commonRequest)

	commonRequest.UserFound = auth.GetAccount() != ""
	commonRequest.FeatureName = featureName

	action.RequestChan <- &action.Action{
		LuaAction:     luaAction,
		Context:       auth.Runtime.Context,
		FinishedChan:  finished,
		HTTPRequest:   auth.Request.HTTPClientRequest,
		HTTPContext:   auth.Request.HTTPClientContext,
		CommonRequest: commonRequest,
	}

	<-finished

	lualib.PutCommonRequest(commonRequest)
}
