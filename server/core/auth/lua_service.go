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

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/pipeline"
	"github.com/croessner/nauthilus/v4/server/lualib/subject"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/stats"
	"github.com/croessner/nauthilus/v4/server/util"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

// DefaultLuaSubject executes exact generation-owned Lua subject sources.
//
//goland:nointerface
type DefaultLuaSubject struct{}

// AnalyzeSource executes one exact generation-owned precompiled subject source.
func (DefaultLuaSubject) AnalyzeSource(
	ctx *gin.Context,
	view *core.StateView,
	passDBResult *core.PassDBResult,
	name string,
	prototype *lua.FunctionProto,
	pools *vmpool.Manager,
	poolKey vmpool.PoolKey,
	modules *luaseal.Modules,
) definitions.AuthResult {
	if name == "" || prototype == nil || pools == nil || poolKey == "" {
		return definitions.AuthResultTempFail
	}

	return analyzeLuaSubject(ctx, view, passDBResult, &subject.LuaSubjectSource{
		Name: name, CompiledScript: prototype, Modules: modules,
		Modes: pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth,
	}, pools, poolKey)
}

// analyzeLuaSubject owns one generation-captured Lua subject invocation.
func analyzeLuaSubject(
	ctx *gin.Context,
	view *core.StateView,
	passDBResult *core.PassDBResult,
	source *subject.LuaSubjectSource,
	pools *vmpool.Manager,
	poolKey vmpool.PoolKey,
) definitions.AuthResult {
	auth := view.Auth()

	resource := util.RequestResource(ctx, ctx.Request, auth.Request.Service)
	stopTimer := stats.PrometheusTimer(auth.Cfg(), definitions.PromSubject, "lua_subject_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	backendServers := core.ListBackendServers()
	util.DebugModuleWithCfg(auth.Ctx(), auth.Cfg(), auth.Logger(), definitions.DbgEnvironment, definitions.LogKeyMsg, fmt.Sprintf("Active backend servers: %d", len(backendServers)))

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	defer lualib.PutCommonRequest(commonRequest)

	auth.FillCommonRequest(commonRequest)
	prepareLuaSubjectCommonRequest(commonRequest, passDBResult)

	subjectRequest := newLuaSubjectRequest(ctx, auth, commonRequest, backendServers)

	var (
		subjectResult    bool
		luaBackendResult *lualib.LuaBackendResult
		removeAttributes []string
		err              error
	)

	subjectResult, luaBackendResult, removeAttributes, err = subjectRequest.CallSubjectLuaSource(
		ctx,
		auth.Cfg(),
		auth.Logger(),
		auth.Redis(),
		source,
		pools,
		poolKey,
	)
	if err != nil {
		if result, done := handleLuaSubjectError(auth, err); done {
			return result
		}
	} else if result, done := applyLuaSubjectResult(auth, subjectRequest, luaBackendResult, removeAttributes, passDBResult, subjectResult); done {
		return result
	}

	if passDBResult.Authenticated {
		return definitions.AuthResultOK
	}

	return definitions.AuthResultFail
}

// prepareLuaSubjectCommonRequest applies passDB values that may change after FillCommonRequest.
func prepareLuaSubjectCommonRequest(commonRequest *lualib.CommonRequest, passDBResult *core.PassDBResult) {
	if commonRequest.AccountField != "" {
		commonRequest.AccountField = definitions.MetaUserAccount
	}

	commonRequest.UserFound = passDBResult.UserFound
	commonRequest.Authenticated = passDBResult.Authenticated
}

// newLuaSubjectRequest builds the Lua subject request from AuthState.
func newLuaSubjectRequest(
	ctx *gin.Context,
	auth *core.AuthState,
	commonRequest *lualib.CommonRequest,
	backendServers []*config.BackendServer,
) *subject.Request {
	return &subject.Request{
		Session:              auth.Runtime.GUID,
		Username:             auth.Request.Username,
		Password:             auth.PasswordBytes(),
		ClientIP:             auth.Request.ClientIP,
		AccountName:          auth.GetAccount(),
		AdditionalAttributes: auth.Runtime.AdditionalAttributes,
		BackendServers:       backendServers,
		UsedBackendAddr:      &auth.Runtime.UsedBackendIP,
		UsedBackendPort:      &auth.Runtime.UsedBackendPort,
		Logs:                 nil,
		Context:              auth.Runtime.Context,
		CommonRequest:        commonRequest,
		Tolerate:             auth.Tolerate(),
		ScriptRecorder:       auth.PolicyScriptRecorder(ctx),
		PolicyContext:        auth.PolicyDecisionContext(ctx),
	}
}

// handleLuaSubjectError maps Lua subject errors to auth results.
func handleLuaSubjectError(auth *core.AuthState, err error) (definitions.AuthResult, bool) {
	logLuaSubjectError(auth, err)
	auth.Runtime.Authorized = false

	return definitions.AuthResultTempFail, true
}

// logLuaSubjectError logs Lua stack traces when available.
func logLuaSubjectError(auth *core.AuthState, err error) {
	if ae, ok := stderrors.AsType[*lua.ApiError](err); ok && ae != nil {
		level.Error(auth.Logger()).Log(
			definitions.LogKeyGUID, auth.Runtime.GUID,
			definitions.LogKeyMsg, "Error calling Lua subject source",
			definitions.LogKeyError, ae.Error(),
			"stacktrace", ae.StackTrace,
		)
	}
}

// applyLuaSubjectResult applies successful Lua subject output to AuthState.
func applyLuaSubjectResult(
	auth *core.AuthState,
	subjectRequest *subject.Request,
	luaBackendResult *lualib.LuaBackendResult,
	removeAttributes []string,
	passDBResult *core.PassDBResult,
	subjectResult bool,
) (definitions.AuthResult, bool) {
	appendLuaSubjectLogs(auth, subjectRequest)
	updateLuaSubjectStatusMessage(auth, subjectRequest)
	removeLuaSubjectAttributes(auth, removeAttributes)
	applyLuaBackendResult(auth, luaBackendResult, passDBResult)

	if subjectResult {
		auth.Runtime.Authorized = false

		return definitions.AuthResultFail, true
	}

	auth.Runtime.Authorized = true
	auth.Runtime.UsedBackendIP = *subjectRequest.UsedBackendAddr
	auth.Runtime.UsedBackendPort = *subjectRequest.UsedBackendPort

	return definitions.AuthResultUnset, false
}

// appendLuaSubjectLogs appends Lua subject logs while preserving allocation behavior.
func appendLuaSubjectLogs(auth *core.AuthState, subjectRequest *subject.Request) {
	if subjectRequest.Logs == nil || len(*subjectRequest.Logs) == 0 {
		return
	}

	additionalLogsLen := len(auth.Runtime.AdditionalLogs)
	newAdditionalLogs := make([]any, additionalLogsLen+len(*subjectRequest.Logs))
	copy(newAdditionalLogs, auth.Runtime.AdditionalLogs)
	auth.Runtime.AdditionalLogs = newAdditionalLogs[:additionalLogsLen]

	for index := range *subjectRequest.Logs {
		auth.Runtime.AdditionalLogs = append(auth.Runtime.AdditionalLogs, (*subjectRequest.Logs)[index])
	}
}

// updateLuaSubjectStatusMessage applies a changed Lua status message.
func updateLuaSubjectStatusMessage(auth *core.AuthState, subjectRequest *subject.Request) {
	if statusMessage := subjectRequest.StatusMessage; *statusMessage != auth.Runtime.StatusMessage {
		auth.Runtime.StatusMessage = *statusMessage
	}
}

// removeLuaSubjectAttributes deletes attributes requested by Lua.
func removeLuaSubjectAttributes(auth *core.AuthState, removeAttributes []string) {
	for _, attributeName := range removeAttributes {
		auth.DeleteAttribute(attributeName)
	}
}

// applyLuaBackendResult merges Lua backend attributes and groups.
func applyLuaBackendResult(auth *core.AuthState, luaBackendResult *lualib.LuaBackendResult, passDBResult *core.PassDBResult) {
	if luaBackendResult == nil {
		return
	}

	applyLuaBackendAttributes(auth, luaBackendResult)
	applyLuaBackendGroups(auth, luaBackendResult, passDBResult)
}

// applyLuaBackendAttributes merges Lua backend attributes into AuthState.
func applyLuaBackendAttributes(auth *core.AuthState, luaBackendResult *lualib.LuaBackendResult) {
	if luaBackendResult.Attributes == nil {
		return
	}

	for key, value := range luaBackendResult.Attributes {
		if keyName, assertOk := key.(string); assertOk {
			auth.SetAttributeIfAbsent(keyName, value)
		}
	}
}

// applyLuaBackendGroups merges Lua backend group results into AuthState and passDBResult.
func applyLuaBackendGroups(auth *core.AuthState, luaBackendResult *lualib.LuaBackendResult, passDBResult *core.PassDBResult) {
	if len(luaBackendResult.Groups) == 0 && len(luaBackendResult.GroupDistinguishedNames) == 0 {
		return
	}

	mergedGroups := append(auth.GetGroups(), luaBackendResult.Groups...)
	mergedGroupDistinguishedNames := append(auth.GetGroupDistinguishedNames(), luaBackendResult.GroupDistinguishedNames...)
	auth.SetResolvedGroups(mergedGroups, mergedGroupDistinguishedNames)
	passDBResult.Groups = auth.GetGroups()
	passDBResult.GroupDistinguishedNames = auth.GetGroupDistinguishedNames()
}
