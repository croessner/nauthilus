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
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"net/http"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/subject"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// DefaultLuaSubject mirrors the previous AuthState.SubjectLua behavior.
// Implemented in subpackage to avoid import cycles; registered via core.RegisterLuaSubject.
//
//goland:nointerface
type DefaultLuaSubject struct{}

// DefaultPostAction mirrors the previous AuthState.PostLuaAction behavior.
//
//goland:nointerface
type DefaultPostAction struct{}

// Analyze implements the Lua subject source logic with identical behavior to the legacy inline method.
func (DefaultLuaSubject) Analyze(ctx *gin.Context, view *core.StateView, passDBResult *core.PassDBResult) definitions.AuthResult {
	auth := view.Auth()

	if !auth.Cfg().HaveLuaSubjectSources() {
		// No subject sources configured, so the backend result stands.
		auth.Runtime.Authorized = true

		if passDBResult.Authenticated {
			return definitions.AuthResultOK
		}

		return definitions.AuthResultFail
	}

	stopTimer := stats.PrometheusTimer(auth.Cfg(), definitions.PromSubject, "lua_subject_request_total", ctx.FullPath())
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

	subjectResult, luaBackendResult, removeAttributes, err := subjectRequest.CallSubjectLua(ctx, auth.Cfg(), auth.Logger(), auth.Redis())
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
		ScriptRecorder:       auth.PolicyScriptRecorder(ctx),
		PolicyContext:        auth.PolicyDecisionContext(ctx),
	}
}

// handleLuaSubjectError maps Lua subject errors to auth results.
func handleLuaSubjectError(auth *core.AuthState, err error) (definitions.AuthResult, bool) {
	if stderrors.Is(err, errors.ErrNoSubjectSourcesDefined) {
		auth.Runtime.Authorized = true

		return definitions.AuthResultUnset, false
	}

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

// Run implements the Lua post action dispatch with identical behavior to the legacy inline method.
func (DefaultPostAction) Run(input core.PostActionInput) {
	auth := input.View.Auth()
	passDBResult := input.Result

	if !canRunLuaPostAction(auth, passDBResult) {
		return
	}

	postActionRequest := util.DetachedHTTPRequest(context.TODO(), auth.Request.HTTPClientRequest)
	if util.IsHTTPRequestCanceled(auth.Logger(), postActionRequest, auth.Runtime.GUID, "schedule.lua_post_action") {
		return
	}

	lspan := startLuaPostActionSpan(auth, passDBResult)
	defer lspan.End()

	if !luaPostActionReadyWithContext(auth, auth.Runtime.Context) {
		return
	}

	cr := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(cr)

	auth.FillCommonRequest(cr)
	prepareLuaPostActionCommonRequest(auth, input, passDBResult, cr)

	args := newLuaPostActionArgs(auth, postActionRequest, cr)

	go auth.RunLuaPostAction(args)
}

// RunPlanStep executes Lua post-actions synchronously inside the shared post-action plan.
func (DefaultPostAction) RunPlanStep(input core.PostActionPlanInput) (pluginapi.RuntimeDelta, bool) {
	auth := input.View.Auth()
	passDBResult := input.Result

	if !canRunLuaPostAction(auth, passDBResult) {
		return pluginapi.RuntimeDelta{}, true
	}

	postActionRequest := util.DetachedHTTPRequest(context.TODO(), auth.Request.HTTPClientRequest)
	if util.IsHTTPRequestCanceled(auth.Logger(), postActionRequest, auth.Runtime.GUID, "schedule.lua_post_action_plan") {
		return pluginapi.RuntimeDelta{}, false
	}

	lspan := startLuaPostActionSpan(auth, passDBResult)
	defer lspan.End()

	luaCtx := lualib.NewContext()
	luaCtx.ApplyDelta(lualib.ContextDelta{Set: input.Runtime})
	before := luaCtx.Snapshot()

	if !luaPostActionReadyWithContext(auth, luaCtx) {
		return pluginapi.RuntimeDelta{}, true
	}

	cr := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(cr)

	auth.FillCommonRequest(cr)
	prepareLuaPostActionCommonRequest(auth, input.PostActionInput, passDBResult, cr)

	args := newLuaPostActionArgsWithContext(auth, postActionRequest, cr, luaCtx)
	auth.RunLuaPostAction(args)

	return luaContextDeltaToRuntimeDelta(luaCtx.Diff(before)), true
}

// canRunLuaPostAction checks whether a post-action request should be scheduled.
func canRunLuaPostAction(auth *core.AuthState, passDBResult *core.PassDBResult) bool {
	return passDBResult != nil && auth.Cfg().HaveLuaActions()
}

// startLuaPostActionSpan starts the Lua post-action span and annotates backend state.
func startLuaPostActionSpan(auth *core.AuthState, passDBResult *core.PassDBResult) trace.Span {
	tr := monittrace.New("nauthilus/auth")
	_, lspan := tr.Start(auth.Ctx(), "auth.lua.post_action",
		attribute.String("service", auth.Request.Service),
		attribute.String("username", auth.Request.Username),
	)

	lspan.SetAttributes(
		attribute.Bool("authenticated", passDBResult.Authenticated),
		attribute.Bool("user_found", passDBResult.UserFound),
	)

	if passDBResult.BackendName != "" {
		lspan.SetAttributes(attribute.String("backend", passDBResult.BackendName))
	} else {
		lspan.SetAttributes(attribute.String("backend", passDBResult.Backend.String()))
	}

	return lspan
}

// luaPostActionReadyWithContext verifies required request fields and Lua context before scheduling work.
func luaPostActionReadyWithContext(auth *core.AuthState, luaCtx *lualib.Context) bool {
	return auth.Request.Protocol != nil && auth.Request.HTTPClientRequest != nil && luaCtx != nil
}

// prepareLuaPostActionCommonRequest applies post-action specific common request values.
func prepareLuaPostActionCommonRequest(
	auth *core.AuthState,
	input core.PostActionInput,
	passDBResult *core.PassDBResult,
	cr *lualib.CommonRequest,
) {
	cr.UserFound = passDBResult.UserFound || auth.GetAccount() != ""
	cr.Authenticated = passDBResult.Authenticated
	cr.EnvironmentRejected = input.EnvironmentRejected
	cr.EnvironmentStageExpected = input.EnvironmentStageExpected
	cr.SubjectStageExpected = input.SubjectStageExpected
	applyLuaPostActionStatus(auth, cr)
}

// applyLuaPostActionStatus fills status message and HTTP status for Lua post-actions.
func applyLuaPostActionStatus(auth *core.AuthState, cr *lualib.CommonRequest) {
	if auth.Runtime.StatusMessage == "" {
		if cr.Authenticated {
			auth.Runtime.StatusMessage = authStatusMessageOK
		} else {
			auth.Runtime.StatusMessage = definitions.PasswordFail
		}
	}

	if cr.Authenticated {
		cr.HTTPStatus = auth.Runtime.StatusCodeOK
	} else {
		cr.HTTPStatus = auth.Runtime.StatusCodeFail
	}
}

// newLuaPostActionArgs copies the common request into detached post-action args.
func newLuaPostActionArgs(auth *core.AuthState, postActionRequest *http.Request, cr *lualib.CommonRequest) core.PostActionArgs {
	return newLuaPostActionArgsWithContext(auth, postActionRequest, cr, auth.Runtime.Context)
}

// newLuaPostActionArgsWithContext copies the common request into detached post-action args.
func newLuaPostActionArgsWithContext(
	auth *core.AuthState,
	postActionRequest *http.Request,
	cr *lualib.CommonRequest,
	luaCtx *lualib.Context,
) core.PostActionArgs {
	requestCopy := luaPostActionRequestCopy(cr)

	return core.PostActionArgs{
		Context:       luaCtx,
		HTTPRequest:   postActionRequest,
		ParentSpan:    trace.SpanContextFromContext(auth.Ctx()),
		StatusMessage: auth.Runtime.StatusMessage,
		Request:       requestCopy,
	}
}

// luaPostActionRequestCopy returns an isolated copy for detached execution.
func luaPostActionRequestCopy(cr *lualib.CommonRequest) lualib.CommonRequest {
	requestCopy := *cr
	if len(cr.Password) > 0 {
		requestCopy.Password = bytes.Clone(cr.Password)
	} else {
		requestCopy.Password = nil
	}

	return requestCopy
}

// luaContextDeltaToRuntimeDelta converts Lua context changes into plugin runtime changes.
func luaContextDeltaToRuntimeDelta(delta lualib.ContextDelta) pluginapi.RuntimeDelta {
	runtimeDelta := pluginapi.RuntimeDelta{}
	if len(delta.Set) > 0 {
		runtimeDelta.Set = make(map[string]any, len(delta.Set))
		for key, value := range delta.Set {
			runtimeDelta.Set[key] = luaContextRuntimeValue(value)
		}
	}

	if len(delta.Delete) > 0 {
		runtimeDelta.Delete = append([]string(nil), delta.Delete...)
	}

	return runtimeDelta
}

// luaContextRuntimeValue normalizes Lua table maps to runtime-compatible string-keyed maps.
func luaContextRuntimeValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		normalized := make(map[string]any, len(typed))
		for key, nested := range typed {
			normalized[key] = luaContextRuntimeValue(nested)
		}

		return normalized
	case map[any]any:
		normalized := make(map[string]any, len(typed))
		for key, nested := range typed {
			normalized[fmt.Sprint(key)] = luaContextRuntimeValue(nested)
		}

		return normalized
	case []any:
		normalized := make([]any, len(typed))
		for index, nested := range typed {
			normalized[index] = luaContextRuntimeValue(nested)
		}

		return normalized
	case []string:
		return append([]string(nil), typed...)
	default:
		return typed
	}
}
