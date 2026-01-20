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
	stderrors "errors"
	"fmt"

	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/filter"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/trace"
)

// DefaultLuaFilter mirrors the previous AuthState.FilterLua behavior.
// Implemented in subpackage to avoid import cycles; registered via core.RegisterLuaFilter.
//
//goland:nointerface
type DefaultLuaFilter struct{}

// DefaultPostAction mirrors the previous AuthState.PostLuaAction behavior.
//
//goland:nointerface
type DefaultPostAction struct{}

// Filter implements the Lua filter logic with identical behavior to the legacy inline method.
func (DefaultLuaFilter) Filter(ctx *gin.Context, view *core.StateView, passDBResult *core.PassDBResult) definitions.AuthResult {
	auth := view.Auth()

	if !auth.Cfg().HaveLuaFilters() {
		// No filters configured → treat as authorized
		auth.Runtime.Authorized = true

		if passDBResult.Authenticated {
			return definitions.AuthResultOK
		}

		return definitions.AuthResultFail
	}

	stopTimer := stats.PrometheusTimer(auth.Cfg(), definitions.PromFilter, "lua_filter_request_total")
	if stopTimer != nil {
		defer stopTimer()
	}

	backendServers := core.ListBackendServers()
	util.DebugModuleWithCfg(auth.Ctx(), auth.Cfg(), auth.Logger(), definitions.DbgFeature, definitions.LogKeyMsg, fmt.Sprintf("Active backend servers: %d", len(backendServers)))

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()
	auth.FillCommonRequest(commonRequest)

	// UserFound and Authenticated are special because they might have been
	// updated by the passDB result after FillCommonRequest was called.
	commonRequest.UserFound = passDBResult.UserFound
	commonRequest.Authenticated = passDBResult.Authenticated

	filterRequest := &filter.Request{
		Session:            auth.Runtime.GUID,
		Username:           auth.Request.Username,
		Password:           auth.Request.Password,
		ClientIP:           auth.Request.ClientIP,
		AccountName:        auth.GetAccount(),
		AdditionalFeatures: auth.Runtime.AdditionalFeatures,
		BackendServers:     backendServers,
		UsedBackendAddr:    &auth.Runtime.UsedBackendIP,
		UsedBackendPort:    &auth.Runtime.UsedBackendPort,
		Logs:               nil,
		Context:            auth.Runtime.Context,
		CommonRequest:      commonRequest,
	}

	filterResult, luaBackendResult, removeAttributes, err := filterRequest.CallFilterLua(ctx, auth.Cfg(), auth.Logger(), auth.Redis())
	if err != nil {
		if !stderrors.Is(err, errors.ErrNoFiltersDefined) {
			// Include Lua stacktrace when available
			var ae *lua.ApiError
			if stderrors.As(err, &ae) && ae != nil {
				level.Error(auth.Logger()).Log(
					definitions.LogKeyGUID, auth.Runtime.GUID,
					definitions.LogKeyMsg, "Error calling Lua filter",
					definitions.LogKeyError, ae.Error(),
					"stacktrace", ae.StackTrace,
				)
			}

			// Return the CommonRequest to the pool even if there's an error
			lualib.PutCommonRequest(commonRequest)

			// error during filter execution → not authorized
			auth.Runtime.Authorized = false

			return definitions.AuthResultTempFail
		}

		// Explicitly authorized when no filters are defined
		auth.Runtime.Authorized = true
	} else {
		if filterRequest.Logs != nil && len(*filterRequest.Logs) > 0 {
			// Pre-allocate the AdditionalLogs slice to avoid continuous reallocation
			additionalLogsLen := len(auth.Runtime.AdditionalLogs)
			newAdditionalLogs := make([]any, additionalLogsLen+len(*filterRequest.Logs))
			copy(newAdditionalLogs, auth.Runtime.AdditionalLogs)
			auth.Runtime.AdditionalLogs = newAdditionalLogs[:additionalLogsLen]

			for index := range *filterRequest.Logs {
				auth.Runtime.AdditionalLogs = append(auth.Runtime.AdditionalLogs, (*filterRequest.Logs)[index])
			}
		}

		if statusMessage := filterRequest.StatusMessage; *statusMessage != auth.Runtime.StatusMessage {
			auth.Runtime.StatusMessage = *statusMessage
		}

		for _, attributeName := range removeAttributes {
			auth.DeleteAttribute(attributeName)
		}

		if luaBackendResult != nil {
			// XXX: We currently only support changing attributes from the AuthState object.
			if (*luaBackendResult).Attributes != nil {
				for key, value := range (*luaBackendResult).Attributes {
					if keyName, assertOk := key.(string); assertOk {
						auth.SetAttributeIfAbsent(keyName, value)
					}
				}
			}
		}

		if filterResult {
			auth.Runtime.Authorized = false

			// Return the CommonRequest to the pool before returning
			lualib.PutCommonRequest(commonRequest)

			return definitions.AuthResultFail
		}

		// filters accepted → authorized
		auth.Runtime.Authorized = true

		auth.Runtime.UsedBackendIP = *filterRequest.UsedBackendAddr
		auth.Runtime.UsedBackendPort = *filterRequest.UsedBackendPort
	}

	// Return the CommonRequest to the pool
	lualib.PutCommonRequest(commonRequest)

	if passDBResult.Authenticated {
		return definitions.AuthResultOK
	}

	return definitions.AuthResultFail
}

// Run implements the Lua post action dispatch with identical behavior to the legacy inline method.
func (DefaultPostAction) Run(input core.PostActionInput) {
	auth := input.View.Auth()
	passDBResult := input.Result

	if !auth.Cfg().HaveLuaActions() {
		return
	}

	// Make sure we have all the required values and they're not nil
	if auth.Request.Protocol == nil || auth.Request.HTTPClientRequest == nil || auth.Runtime.Context == nil {
		return
	}

	// Get a CommonRequest from the pool
	cr := lualib.GetCommonRequest()
	auth.FillCommonRequest(cr)

	// UserFound and Authenticated are special because they might have been
	// updated by the passDB result after FillCommonRequest was called.
	cr.UserFound = passDBResult.UserFound || auth.GetAccount() != ""
	cr.Authenticated = passDBResult.Authenticated

	if auth.Runtime.StatusMessage == "" {
		if cr.Authenticated {
			auth.Runtime.StatusMessage = "OK"
		} else {
			auth.Runtime.StatusMessage = definitions.PasswordFail
		}
	}

	if cr.Authenticated {
		cr.HTTPStatus = auth.Runtime.StatusCodeOK
	} else {
		cr.HTTPStatus = auth.Runtime.StatusCodeFail
	}

	args := core.PostActionArgs{
		Context:       auth.Runtime.Context,
		HTTPRequest:   auth.Request.HTTPClientRequest,
		ParentSpan:    trace.SpanContextFromContext(auth.Ctx()),
		StatusMessage: auth.Runtime.StatusMessage,
		Request:       *cr,
	}

	lualib.PutCommonRequest(cr)

	go auth.RunLuaPostAction(args)
}
