// Copyright (C) 2025 Christian Rößner
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

package luatest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/croessner/nauthilus/v3/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

// TestRunner manages Lua script testing.
type TestRunner struct {
	scriptPath   string
	callbackType string
	mockDataPath string
	mockData     *MockData
	logger       *MockLogger
}

// NewTestRunner creates a new TestRunner.
func NewTestRunner(scriptPath, callbackType, mockDataPath string) (*TestRunner, error) {
	runner := &TestRunner{
		scriptPath:   scriptPath,
		callbackType: callbackType,
		mockDataPath: mockDataPath,
		logger:       &MockLogger{Logs: []string{}, StatusMessages: []string{}},
	}

	if mockDataPath != "" {
		if err := runner.loadMockData(); err != nil {
			return nil, fmt.Errorf("failed to load mock data: %w", err)
		}
	} else {
		runner.mockData = &MockData{}
	}

	return runner, nil
}

// loadMockData loads mock data from JSON file.
func (tr *TestRunner) loadMockData() error {
	data, err := os.ReadFile(tr.mockDataPath)
	if err != nil {
		return fmt.Errorf("failed to read mock data file: %w", err)
	}

	tr.mockData = &MockData{}
	if err := json.Unmarshal(data, tr.mockData); err != nil {
		return fmt.Errorf("failed to parse mock data JSON: %w", err)
	}

	return nil
}

// Run executes the Lua script test.
func (tr *TestRunner) Run() (*TestResult, error) {
	L, cleanup, err := tr.prepareLuaState()
	if err != nil {
		return nil, err
	}

	defer L.Close()
	defer cleanup()

	result, err := tr.executeLuaScript(L)
	if err != nil {
		return nil, err
	}

	tr.captureBackendSelection(result)
	tr.validateRuntimeExpectations(result)
	tr.validateExpectedOutput(result)

	return result, nil
}

// prepareLuaState creates a Lua state and installs all test modules.
func (tr *TestRunner) prepareLuaState() (*lua.LState, func(), error) {
	L := lua.NewState()
	tr.configureLuaPackagePath(L)

	cleanup, err := SetupMockModules(L, tr.mockData, tr.logger)
	if err != nil {
		L.Close()

		return nil, nil, fmt.Errorf("failed to setup Lua test modules: %w", err)
	}

	return L, cleanup, nil
}

// executeLuaScript loads the script and runs the configured callback.
func (tr *TestRunner) executeLuaScript(L *lua.LState) (*TestResult, error) {
	if err := L.DoFile(tr.scriptPath); err != nil {
		return nil, fmt.Errorf("failed to load Lua script: %w", err)
	}

	result, err := tr.executeCallback(L)
	if err != nil {
		return &TestResult{
			Success:        false,
			Logs:           tr.logger.Logs,
			StatusMessages: tr.logger.StatusMessages,
			Errors:         []error{err},
		}, nil
	}

	result.Logs = tr.logger.Logs
	result.StatusMessages = tr.logger.StatusMessages

	return result, nil
}

// captureBackendSelection copies backend-selection runtime state into the result.
func (tr *TestRunner) captureBackendSelection(result *TestResult) {
	if tr.mockData == nil || tr.mockData.Backend == nil {
		return
	}

	if tr.mockData.Backend.RuntimeSelectedHost != "" {
		selectedHost := tr.mockData.Backend.RuntimeSelectedHost
		result.UsedBackendAddress = &selectedHost
	}

	if tr.mockData.Backend.RuntimeSelectedPort != nil {
		selectedPort := *tr.mockData.Backend.RuntimeSelectedPort
		result.UsedBackendPort = &selectedPort
	}
}

type luaTestExpectationValidator interface {
	ValidateComplete() error
}

// validateRuntimeExpectations checks expected_calls for all configured mocks.
func (tr *TestRunner) validateRuntimeExpectations(result *TestResult) {
	for _, validator := range tr.runtimeExpectationValidators() {
		if err := validator.ValidateComplete(); err != nil {
			result.Success = false
			result.Errors = append(result.Errors, err)
		}
	}
}

// runtimeExpectationValidators returns mock validators in stable validation order.
func (tr *TestRunner) runtimeExpectationValidators() []luaTestExpectationValidator {
	if tr.mockData == nil {
		return nil
	}

	return []luaTestExpectationValidator{
		tr.mockData.DB,
		tr.mockData.Context,
		tr.mockData.Redis,
		tr.mockData.Policy,
		tr.mockData.I18N,
		tr.mockData.LDAP,
		tr.mockData.Backend,
		tr.mockData.BackendResult,
		tr.mockData.HTTPRequest,
		tr.mockData.HTTPResponse,
		tr.mockData.HTTPClient,
		tr.mockData.DNS,
		tr.mockData.OpenTelemetry,
		tr.mockData.BruteForce,
		tr.mockData.Psnet,
		tr.mockData.Prometheus,
		tr.mockData.Util,
		tr.mockData.Cache,
		tr.mockData.Misc,
		tr.mockData.Password,
		tr.mockData.SoftWhitelist,
		tr.mockData.Mail,
	}
}

// validateExpectedOutput applies expected output assertions when configured.
func (tr *TestRunner) validateExpectedOutput(result *TestResult) {
	if tr.mockData == nil || tr.mockData.ExpectedOutput == nil {
		return
	}

	tr.validateOutput(result)
}

// configureLuaPackagePath extends package.path so local companion modules can be required
// without relying on external LUA_PATH configuration.
func (tr *TestRunner) configureLuaPackagePath(L *lua.LState) {
	if tr == nil || L == nil || tr.scriptPath == "" {
		return
	}

	scriptDir := filepath.Dir(tr.scriptPath)
	if scriptDir == "." || scriptDir == "" {
		return
	}

	pkg := L.GetGlobal("package")

	pkgTbl, ok := pkg.(*lua.LTable)
	if !ok {
		return
	}

	currentPath := lua.LVAsString(L.GetField(pkgTbl, "path"))
	extraPatterns := []string{
		filepath.ToSlash(filepath.Join(scriptDir, "?.lua")),
		filepath.ToSlash(filepath.Join(scriptDir, "?/init.lua")),
		filepath.ToSlash(filepath.Join(scriptDir, "lib", "?.lua")),
		filepath.ToSlash(filepath.Join(scriptDir, "lib", "?/init.lua")),
		filepath.ToSlash(filepath.Join(scriptDir, "../../../../lua-plugins.d/share", "?.lua")),
		filepath.ToSlash(filepath.Join(scriptDir, "../../../../lua-plugins.d/share", "?/init.lua")),
		filepath.ToSlash(filepath.Join("server", "lua-plugins.d", "share", "?.lua")),
	}

	newPath := strings.Join(extraPatterns, ";")
	if currentPath != "" {
		newPath = newPath + ";" + currentPath
	}

	L.SetField(pkgTbl, "path", lua.LString(newPath))
}

// createRequestTable creates a Lua table with request data from mock context.
func (tr *TestRunner) createRequestTable(L *lua.LState) *lua.LTable {
	requestTable := L.NewTable()

	if tr.mockData.Context != nil {
		ctx := tr.mockData.Context

		L.SetField(requestTable, "username", lua.LString(ctx.Username))
		L.SetField(requestTable, "password", lua.LString(ctx.Password))
		L.SetField(requestTable, "client_ip", lua.LString(ctx.ClientIP))
		L.SetField(requestTable, "client_port", lua.LString(ctx.ClientPort))
		L.SetField(requestTable, "client_host", lua.LString(ctx.ClientHost))
		L.SetField(requestTable, "client_id", lua.LString(ctx.ClientID))
		L.SetField(requestTable, "local_ip", lua.LString(ctx.LocalIP))
		L.SetField(requestTable, "local_port", lua.LString(ctx.LocalPort))
		L.SetField(requestTable, "service", lua.LString(ctx.Service))
		L.SetField(requestTable, "protocol", lua.LString(ctx.Protocol))
		L.SetField(requestTable, "user_agent", lua.LString(ctx.UserAgent))
		L.SetField(requestTable, "session", lua.LString(ctx.Session))
		L.SetField(requestTable, "debug", lua.LBool(ctx.Debug))
		L.SetField(requestTable, "no_auth", lua.LBool(ctx.NoAuth))
		L.SetField(requestTable, "authenticated", lua.LBool(ctx.Authenticated))
		L.SetField(requestTable, "user_found", lua.LBool(ctx.UserFound))
		L.SetField(requestTable, "account", lua.LString(ctx.Account))
		L.SetField(requestTable, "unique_user_id", lua.LString(ctx.UniqueUserID))
		L.SetField(requestTable, "display_name", lua.LString(ctx.DisplayName))
		L.SetField(requestTable, "status_message", lua.LString(ctx.StatusMessage))
		L.SetField(requestTable, "brute_force_count", lua.LNumber(ctx.BruteForceCount))

		if ctx.Debug {
			L.SetField(requestTable, "log_level", lua.LString("debug"))
		} else {
			L.SetField(requestTable, "log_level", lua.LString("info"))
		}

		L.SetField(requestTable, "log_format", lua.LString("json"))

		// Keep old nested shape for backwards compatibility.
		loggingTable := L.NewTable()
		L.SetField(loggingTable, "log_level", L.GetField(requestTable, "log_level"))
		L.SetField(loggingTable, "log_format", L.GetField(requestTable, "log_format"))
		L.SetField(requestTable, "logging", loggingTable)
	}

	return requestTable
}

// resolveLuaFunction looks up a callback function first in __NAUTH_REQ_ENV, then in _G.
func resolveLuaFunction(L *lua.LState, functionName string) lua.LValue {
	if reqEnv := L.GetGlobal("__NAUTH_REQ_ENV"); reqEnv != nil && reqEnv.Type() == lua.LTTable {
		if fn := L.GetField(reqEnv, functionName); fn != nil && fn != lua.LNil {
			return fn
		}
	}

	return L.GetGlobal(functionName)
}

// executeCallback calls the appropriate Lua function based on callback type.
func (tr *TestRunner) executeCallback(L *lua.LState) (*TestResult, error) {
	result := &TestResult{
		Success: false,
		Errors:  []error{},
	}

	switch tr.callbackType {
	case "subject":
		return tr.executeSubject(L)
	case "environment":
		return tr.executeEnvironment(L)
	case "action":
		return tr.executeAction(L)
	case "backend":
		return tr.executeBackend(L)
	case "hook":
		return tr.executeHook(L)
	case "cache_flush":
		return tr.executeCacheFlush(L)
	default:
		return result, fmt.Errorf("unknown callback type: %s", tr.callbackType)
	}
}

// executeSubject executes a subject source callback.
func (tr *TestRunner) executeSubject(L *lua.LState) (*TestResult, error) {
	result := &TestResult{Success: false}

	fn := resolveLuaFunction(L, definitions.LuaFnCallSubject)
	if fn.Type() != lua.LTFunction {
		return result, fmt.Errorf("%s function not found in script", definitions.LuaFnCallSubject)
	}

	// Create request table
	requestTable := tr.createRequestTable(L)

	// Call the subject source with request table
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    2,
		Protect: true,
	}, requestTable); err != nil {
		return result, fmt.Errorf("subject source execution failed: %w", err)
	}

	actionValue := L.Get(-2)
	resultValue := L.Get(-1)
	L.Pop(2)

	if actionValue.Type() == lua.LTBool && resultValue.Type() == lua.LTNumber {
		subjectRejected := lua.LVAsBool(actionValue)
		subjectResult := int(lua.LVAsNumber(resultValue))

		result.SubjectRejected = &subjectRejected
		result.SubjectResult = &subjectResult
		result.Success = true
	} else {
		return result, fmt.Errorf(
			"subject source returned unexpected types: action=%s result=%s",
			actionValue.Type(),
			resultValue.Type(),
		)
	}

	return result, nil
}

// executeEnvironment executes an environment source callback.
func (tr *TestRunner) executeEnvironment(L *lua.LState) (*TestResult, error) {
	result := &TestResult{Success: false}

	fn := resolveLuaFunction(L, definitions.LuaFnCallEnvironment)
	if fn.Type() != lua.LTFunction {
		return result, fmt.Errorf("%s function not found in script", definitions.LuaFnCallEnvironment)
	}

	// Create request table
	requestTable := tr.createRequestTable(L)

	// Call the environment source with request table
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    3,
		Protect: true,
	}, requestTable); err != nil {
		return result, fmt.Errorf("environment source execution failed: %w", err)
	}

	triggerValue := L.Get(-3)
	abortValue := L.Get(-2)
	statusValue := L.Get(-1)
	L.Pop(3)

	if triggerValue.Type() == lua.LTBool && abortValue.Type() == lua.LTBool && statusValue.Type() == lua.LTNumber {
		environmentTriggered := lua.LVAsBool(triggerValue)
		environmentAbort := lua.LVAsBool(abortValue)
		environmentResult := int(lua.LVAsNumber(statusValue))

		result.EnvironmentTriggered = &environmentTriggered
		result.EnvironmentAbort = &environmentAbort
		result.EnvironmentResult = &environmentResult
		result.Success = true
	} else {
		return result, fmt.Errorf(
			"environment source returned unexpected types: trigger=%s abort=%s result=%s",
			triggerValue.Type(),
			abortValue.Type(),
			statusValue.Type(),
		)
	}

	return result, nil
}

// executeAction executes an action callback.
func (tr *TestRunner) executeAction(L *lua.LState) (*TestResult, error) {
	result := &TestResult{Success: false}

	// Look for nauthilus_call_action function
	fn := L.GetGlobal("nauthilus_call_action")
	if fn.Type() != lua.LTFunction {
		return result, fmt.Errorf("nauthilus_call_action function not found in script")
	}

	// Create request table
	requestTable := tr.createRequestTable(L)

	// Call the action with request table
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, requestTable); err != nil {
		return result, fmt.Errorf("action execution failed: %w", err)
	}

	// Get the result (actions may return booleans, nil or integer constants)
	ret := L.Get(-1)
	L.Pop(1)

	if ret.Type() == lua.LTBool {
		actionResult := lua.LVAsBool(ret)
		result.ActionResult = &actionResult
		result.Success = true
	} else if ret.Type() == lua.LTNumber {
		// Match production semantics: ACTION_RESULT_OK=0, ACTION_RESULT_FAIL=1
		actionResult := int(lua.LVAsNumber(ret)) == 0
		result.ActionResult = &actionResult
		result.Success = true
	} else if ret.Type() == lua.LTNil {
		// Action succeeded without explicit return
		actionResult := true
		result.ActionResult = &actionResult
		result.Success = true
	} else {
		return result, fmt.Errorf("action returned unexpected type: %s", ret.Type())
	}

	return result, nil
}

// executeBackend executes a backend callback.
func (tr *TestRunner) executeBackend(L *lua.LState) (*TestResult, error) {
	result := &TestResult{Success: false}

	fn := resolveLuaFunction(L, definitions.LuaFnBackendVerifyPassword)
	if fn.Type() != lua.LTFunction {
		return result, fmt.Errorf("%s function not found in script", definitions.LuaFnBackendVerifyPassword)
	}

	// Create request table
	requestTable := tr.createRequestTable(L)

	// Call the backend with request table
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    2,
		Protect: true,
	}, requestTable); err != nil {
		return result, fmt.Errorf("backend execution failed: %w", err)
	}

	returnCodeValue := L.Get(-2)
	backendValue := L.Get(-1)
	L.Pop(2)

	if returnCodeValue.Type() != lua.LTNumber {
		return result, fmt.Errorf("backend returned unexpected status type: %s", returnCodeValue.Type())
	}

	backendReturnCode := int(lua.LVAsNumber(returnCodeValue))
	result.BackendReturnCode = &backendReturnCode

	if backendReturnCode != 0 {
		return result, fmt.Errorf("backend returned non-zero result code: %d", backendReturnCode)
	}

	if backendValue.Type() == lua.LTTable || backendValue.Type() == lua.LTUserData {
		if err := populateBackendResult(result, backendValue); err != nil {
			return result, err
		}

		result.Success = true

		return result, nil
	}

	if backendValue.Type() == lua.LTNil {
		backendResult := false
		result.BackendResult = &backendResult
		result.Success = false

		return result, nil
	}

	return result, fmt.Errorf("backend returned unexpected type: %s", backendValue.Type())
}

// executeHook executes a hook callback.
func (tr *TestRunner) executeHook(L *lua.LState) (*TestResult, error) {
	result := &TestResult{Success: false}

	// Look for nauthilus_run_hook function
	fn := L.GetGlobal("nauthilus_run_hook")
	if fn.Type() != lua.LTFunction {
		return result, fmt.Errorf("nauthilus_run_hook function not found in script")
	}

	// Create request table
	requestTable := tr.createRequestTable(L)

	// Call the hook with request table
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, requestTable); err != nil {
		return result, fmt.Errorf("hook execution failed: %w", err)
	}

	// Get the result (hooks return nil or a result table)
	ret := L.Get(-1)
	L.Pop(1)

	// Hooks typically return nil for success
	if ret.Type() == lua.LTNil || ret.Type() == lua.LTTable {
		hookResult := true
		result.ActionResult = &hookResult // Reuse ActionResult for hooks
		result.Success = true
	} else {
		return result, fmt.Errorf("hook returned unexpected type: %s", ret.Type())
	}

	return result, nil
}

// executeCacheFlush executes the Lua cache flush callback.
func (tr *TestRunner) executeCacheFlush(L *lua.LState) (*TestResult, error) {
	result := &TestResult{Success: false}

	fn := resolveLuaFunction(L, definitions.LuaFnCacheFlushHook)
	if fn.Type() != lua.LTFunction {
		return result, fmt.Errorf("%s function not found in script", definitions.LuaFnCacheFlushHook)
	}

	requestTable := tr.createRequestTable(L)
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    2,
		Protect: true,
	}, requestTable); err != nil {
		return result, fmt.Errorf("cache flush execution failed: %w", err)
	}

	additionalKeysValue := L.Get(-2)
	accountNameValue := L.Get(-1)
	L.Pop(2)

	result.CacheFlushAdditionalKeys = parseCacheFlushAdditionalKeys(additionalKeysValue)
	result.CacheFlushAccountName = parseCacheFlushAccountName(accountNameValue)
	result.Success = true

	return result, nil
}

func parseCacheFlushAdditionalKeys(value lua.LValue) []string {
	additionalKeysTable, ok := value.(*lua.LTable)
	if !ok || additionalKeysTable == nil {
		return nil
	}

	additionalKeys := make([]string, 0, additionalKeysTable.Len())
	for index := 1; index <= additionalKeysTable.Len(); index++ {
		key := additionalKeysTable.RawGetInt(index)
		if key.Type() != lua.LTString {
			continue
		}

		additionalKeys = append(additionalKeys, lua.LVAsString(key))
	}

	return additionalKeys
}

func parseCacheFlushAccountName(value lua.LValue) *string {
	if value.Type() != lua.LTString {
		return nil
	}

	accountName := lua.LVAsString(value)

	return &accountName
}

func populateBackendResult(result *TestResult, value lua.LValue) error {
	backendResult := true
	result.BackendResult = &backendResult

	switch v := value.(type) {
	case *lua.LTable:
		populateBackendResultFromTable(result, v)
		return nil
	case *lua.LUserData:
		return populateBackendResultFromUserData(result, v)
	default:
		return fmt.Errorf("backend returned unexpected type: %s", value.Type())
	}
}

func populateBackendResultFromTable(result *TestResult, table *lua.LTable) {
	authenticatedVal := table.RawGetString(definitions.LuaBackendResultAuthenticated)
	if authenticatedVal.Type() == lua.LTBool {
		authenticated := lua.LVAsBool(authenticatedVal)
		result.BackendAuthenticated = &authenticated
	}

	userFoundVal := table.RawGetString(definitions.LuaBackendResultUserFound)
	if userFoundVal.Type() == lua.LTBool {
		userFound := lua.LVAsBool(userFoundVal)
		result.BackendUserFound = &userFound
	}

	accountFieldVal := table.RawGetString(definitions.LuaBackendResultAccountField)
	if accountFieldVal.Type() == lua.LTString {
		accountField := lua.LVAsString(accountFieldVal)
		result.BackendAccountField = &accountField
	}

	displayNameVal := table.RawGetString(definitions.LuaBackendResultDisplayNameField)
	if displayNameVal.Type() == lua.LTString {
		displayName := lua.LVAsString(displayNameVal)
		result.BackendDisplayName = &displayName
	}

	uniqueUserIDVal := table.RawGetString(definitions.LuaBAckendResultUniqueUserIDField)
	if uniqueUserIDVal.Type() == lua.LTString {
		uniqueUserID := lua.LVAsString(uniqueUserIDVal)
		result.BackendUniqueUserID = &uniqueUserID
	}
}

func populateBackendResultFromUserData(result *TestResult, userData *lua.LUserData) error {
	backendResultObj, ok := userData.Value.(*backendResultMockValue)
	if !ok || backendResultObj == nil {
		return fmt.Errorf("backend returned unexpected userdata payload: %T", userData.Value)
	}

	authenticated := backendResultObj.Authenticated
	userFound := backendResultObj.UserFound
	accountField := backendResultObj.AccountField
	displayName := backendResultObj.DisplayNameField
	uniqueUserID := backendResultObj.UniqueUserIDField

	result.BackendAuthenticated = &authenticated
	result.BackendUserFound = &userFound
	result.BackendAccountField = &accountField
	result.BackendDisplayName = &displayName
	result.BackendUniqueUserID = &uniqueUserID

	return nil
}

// validateOutput validates the test result against expected output.
func (tr *TestRunner) validateOutput(result *TestResult) {
	expected := tr.mockData.ExpectedOutput

	validateScalarExpectedOutput(result, expected)
	validateCacheFlushExpectedOutput(result, expected)
	validateStatusExpectedOutput(result, expected)
	validateLogExpectedOutput(result, expected)
	validateErrorExpectedOutput(result, expected)
}

// validateScalarExpectedOutput checks scalar expected-output fields.
func validateScalarExpectedOutput(result *TestResult, expected *ExpectedOutputMock) {
	appendOptionalPointerMismatch(result, "subject result", expected.SubjectResult, result.SubjectResult, "%d")
	appendOptionalPointerMismatch(result, "subject rejection", expected.SubjectRejected, result.SubjectRejected, "%t")
	appendOptionalPointerMismatch(result, "environment trigger", expected.EnvironmentTriggered, result.EnvironmentTriggered, "%t")
	appendOptionalPointerMismatch(result, "environment abort", expected.EnvironmentAbort, result.EnvironmentAbort, "%t")
	appendOptionalPointerMismatch(result, "environment result", expected.EnvironmentResult, result.EnvironmentResult, "%d")
	appendOptionalPointerMismatch(result, "action result", expected.ActionResult, result.ActionResult, "%t")
	appendOptionalPointerMismatch(result, "backend result", expected.BackendResult, result.BackendResult, "%t")
	appendOptionalPointerMismatch(result, "backend return code", expected.BackendReturnCode, result.BackendReturnCode, "%d")
	appendRequiredPointerMismatch(result, "used backend address", expected.UsedBackendAddress, result.UsedBackendAddress, "%s")
	appendRequiredPointerMismatch(result, "backend authenticated", expected.BackendAuthenticated, result.BackendAuthenticated, "%t")
	appendRequiredPointerMismatch(result, "backend user_found", expected.BackendUserFound, result.BackendUserFound, "%t")
	appendRequiredPointerMismatch(result, "backend account_field", expected.BackendAccountField, result.BackendAccountField, "%s")
	appendRequiredPointerMismatch(result, "backend display_name", expected.BackendDisplayName, result.BackendDisplayName, "%s")
	appendRequiredPointerMismatch(result, "backend unique_user_id", expected.BackendUniqueUserID, result.BackendUniqueUserID, "%s")

	appendRequiredPointerMismatch(result, "cache flush account name", expected.CacheFlushAccountName, result.CacheFlushAccountName, "%s")
	appendRequiredPointerMismatch(result, "used backend port", expected.UsedBackendPort, result.UsedBackendPort, "%d")
}

// validateCacheFlushExpectedOutput checks cache-flush key expectations.
func validateCacheFlushExpectedOutput(result *TestResult, expected *ExpectedOutputMock) {
	if expected.CacheFlushAdditionalKeys != nil {
		if len(expected.CacheFlushAdditionalKeys) != len(result.CacheFlushAdditionalKeys) {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("cache flush additional keys mismatch: expected %d keys, got %d",
					len(expected.CacheFlushAdditionalKeys), len(result.CacheFlushAdditionalKeys)))
		} else {
			for index, expectedKey := range expected.CacheFlushAdditionalKeys {
				resultKey := result.CacheFlushAdditionalKeys[index]
				if expectedKey != resultKey {
					result.Success = false
					result.Errors = append(result.Errors,
						fmt.Errorf("cache flush additional key mismatch at index %d: expected %s, got %s",
							index, expectedKey, resultKey))
				}
			}
		}
	}
}

// validateStatusExpectedOutput checks status message contains and excludes.
func validateStatusExpectedOutput(result *TestResult, expected *ExpectedOutputMock) {
	validateStringExpectations(
		result,
		result.StatusMessages,
		expected.StatusMessageContain,
		expected.StatusMessageNotContain,
		"expected status message not found: %s",
		"unexpected status message found: %s",
	)
}

// validateLogExpectedOutput checks log contains and excludes.
func validateLogExpectedOutput(result *TestResult, expected *ExpectedOutputMock) {
	validateStringExpectations(
		result,
		result.Logs,
		expected.LogsContain,
		expected.LogsNotContain,
		"expected log not found: %s",
		"unexpected log found: %s",
	)
}

// validateStringExpectations checks required and forbidden substrings in ordered output slices.
func validateStringExpectations(
	result *TestResult,
	values []string,
	required []string,
	forbidden []string,
	missingFormat string,
	unexpectedFormat string,
) {
	for _, expectedValue := range required {
		if !containsSubstring(values, expectedValue) {
			result.Success = false
			result.Errors = append(result.Errors, fmt.Errorf(missingFormat, expectedValue))
		}
	}

	for _, unexpectedValue := range forbidden {
		if containsSubstring(values, unexpectedValue) {
			result.Success = false
			result.Errors = append(result.Errors, fmt.Errorf(unexpectedFormat, unexpectedValue))
		}
	}
}

// containsSubstring reports whether any candidate contains the expected substring.
func containsSubstring(values []string, expected string) bool {
	for _, value := range values {
		if strings.Contains(value, expected) {
			return true
		}
	}

	return false
}

// validateErrorExpectedOutput checks expected error presence.
func validateErrorExpectedOutput(result *TestResult, expected *ExpectedOutputMock) {
	if expected.ErrorExpected && len(result.Errors) == 0 {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Errorf("expected error but none occurred"))
	} else if !expected.ErrorExpected && len(result.Errors) > 0 {
		result.Success = false
	}
}

// appendOptionalPointerMismatch compares values only when both expected and actual were produced.
func appendOptionalPointerMismatch[T comparable](result *TestResult, label string, expected, actual *T, format string) {
	if expected == nil || actual == nil {
		return
	}

	appendPointerValueMismatch(result, label, expected, actual, format)
}

// appendRequiredPointerMismatch treats a present expected value as requiring a matching actual value.
func appendRequiredPointerMismatch[T comparable](result *TestResult, label string, expected, actual *T, format string) {
	if expected == nil {
		return
	}

	if actual == nil {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Errorf("%s mismatch: expected %s, got <nil>", label, fmt.Sprintf(format, *expected)))

		return
	}

	appendPointerValueMismatch(result, label, expected, actual, format)
}

// appendPointerValueMismatch records a formatted mismatch for comparable pointer values.
func appendPointerValueMismatch[T comparable](result *TestResult, label string, expected, actual *T, format string) {
	if *expected == *actual {
		return
	}

	result.Success = false
	result.Errors = append(result.Errors, fmt.Errorf(
		"%s mismatch: expected %s, got %s",
		label,
		fmt.Sprintf(format, *expected),
		fmt.Sprintf(format, *actual),
	))
}

// PrintResult prints the test result to stdout.
func (tr *TestRunner) PrintResult(result *TestResult) {
	fmt.Println("\n=== Lua Script Test Results ===")
	fmt.Printf("Script: %s\n", tr.scriptPath)
	fmt.Printf("Callback Type: %s\n", tr.callbackType)
	fmt.Printf("Success: %t\n\n", result.Success)

	printResultScalarFields(result)
	printResultStringSlice("Status Messages", "  [STATUS] %s\n", result.StatusMessages)
	printResultStringSlice("Logs", "  %s\n", result.Logs)
	printResultErrors(result.Errors)

	fmt.Println("\n===============================")
}

// printResultScalarFields prints optional scalar result fields.
func printResultScalarFields(result *TestResult) {
	printOptionalField("Subject Result", result.SubjectResult, "%d")
	printOptionalField("Subject Rejected", result.SubjectRejected, "%t")
	printOptionalField("Environment Triggered", result.EnvironmentTriggered, "%t")
	printOptionalField("Environment Abort", result.EnvironmentAbort, "%t")
	printOptionalField("Environment Result", result.EnvironmentResult, "%d")
	printOptionalField("Action Result", result.ActionResult, "%t")
	printOptionalField("Backend Result", result.BackendResult, "%t")
	printOptionalField("Backend Return Code", result.BackendReturnCode, "%d")
	printOptionalField("Backend Authenticated", result.BackendAuthenticated, "%t")
	printOptionalField("Backend User Found", result.BackendUserFound, "%t")
	printOptionalField("Backend Account Field", result.BackendAccountField, "%s")
	printOptionalField("Backend Display Name", result.BackendDisplayName, "%s")
	printOptionalField("Backend Unique User ID", result.BackendUniqueUserID, "%s")
	printOptionalField("Used Backend Address", result.UsedBackendAddress, "%s")
	printOptionalField("Used Backend Port", result.UsedBackendPort, "%d")
	printOptionalSlice("Cache Flush Additional Keys", result.CacheFlushAdditionalKeys)
	printOptionalField("Cache Flush Account Name", result.CacheFlushAccountName, "%s")
}

// printOptionalField prints a pointer field when it is present.
func printOptionalField[T any](label string, value *T, format string) {
	if value == nil {
		return
	}

	fmt.Printf(label+": "+format+"\n", *value)
}

// printOptionalSlice prints a non-empty slice field.
func printOptionalSlice[T any](label string, values []T) {
	if len(values) == 0 {
		return
	}

	fmt.Printf("%s: %v\n", label, values)
}

// printResultStringSlice prints a titled list of strings.
func printResultStringSlice(title string, format string, values []string) {
	if len(values) == 0 {
		return
	}

	fmt.Printf("\n%s:\n", title)

	for _, value := range values {
		fmt.Printf(format, value)
	}
}

// printResultErrors prints collected result errors.
func printResultErrors(errors []error) {
	if len(errors) == 0 {
		return
	}

	fmt.Println("\nErrors:")

	for _, err := range errors {
		fmt.Printf("  ✗ %s\n", err)
	}
}

// GetExitCode returns the appropriate exit code based on test result.
func (tr *TestRunner) GetExitCode(result *TestResult) int {
	if result.Success {
		return 0
	}

	return 1
}
