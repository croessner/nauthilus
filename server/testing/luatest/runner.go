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

	"github.com/croessner/nauthilus/server/definitions"
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
	L := lua.NewState()
	defer L.Close()

	tr.configureLuaPackagePath(L)

	// Setup mock modules
	cleanup, err := SetupMockModules(L, tr.mockData, tr.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to setup Lua test modules: %w", err)
	}
	defer cleanup()

	// Load and execute the script
	if err = L.DoFile(tr.scriptPath); err != nil {
		return nil, fmt.Errorf("failed to load Lua script: %w", err)
	}

	// Execute the appropriate callback
	result, err := tr.executeCallback(L)
	if err != nil {
		result = &TestResult{
			Success:        false,
			Logs:           tr.logger.Logs,
			StatusMessages: tr.logger.StatusMessages,
			Errors:         []error{err},
		}
	} else {
		result.Logs = tr.logger.Logs
		result.StatusMessages = tr.logger.StatusMessages
	}

	// Capture runtime backend-selection state when the backend mock is active.
	if tr.mockData != nil && tr.mockData.Backend != nil {
		if tr.mockData.Backend.RuntimeSelectedHost != "" {
			selectedHost := tr.mockData.Backend.RuntimeSelectedHost
			result.UsedBackendAddress = &selectedHost
		}

		if tr.mockData.Backend.RuntimeSelectedPort != nil {
			selectedPort := *tr.mockData.Backend.RuntimeSelectedPort
			result.UsedBackendPort = &selectedPort
		}
	}

	// Validate DB mock call expectations when configured.
	if tr.mockData != nil && tr.mockData.DB != nil {
		if err = tr.mockData.DB.ValidateComplete(); err != nil {
			result.Success = false
			result.Errors = append(result.Errors, err)
		}
	}

	// Validate expected_calls for all module mocks.
	if tr.mockData != nil {
		validators := []func() error{
			func() error {
				if tr.mockData.Context != nil {
					return tr.mockData.Context.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.Redis != nil {
					return tr.mockData.Redis.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.LDAP != nil {
					return tr.mockData.LDAP.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.Backend != nil {
					return tr.mockData.Backend.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.BackendResult != nil {
					return tr.mockData.BackendResult.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.HTTPRequest != nil {
					return tr.mockData.HTTPRequest.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.HTTPResponse != nil {
					return tr.mockData.HTTPResponse.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.HTTPClient != nil {
					return tr.mockData.HTTPClient.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.DNS != nil {
					return tr.mockData.DNS.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.OpenTelemetry != nil {
					return tr.mockData.OpenTelemetry.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.BruteForce != nil {
					return tr.mockData.BruteForce.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.Psnet != nil {
					return tr.mockData.Psnet.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.Prometheus != nil {
					return tr.mockData.Prometheus.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.Util != nil {
					return tr.mockData.Util.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.Cache != nil {
					return tr.mockData.Cache.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.Misc != nil {
					return tr.mockData.Misc.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.Password != nil {
					return tr.mockData.Password.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.SoftWhitelist != nil {
					return tr.mockData.SoftWhitelist.ValidateComplete()
				}
				return nil
			},
			func() error {
				if tr.mockData.Mail != nil {
					return tr.mockData.Mail.ValidateComplete()
				}
				return nil
			},
		}

		for _, validate := range validators {
			if vErr := validate(); vErr != nil {
				result.Success = false
				result.Errors = append(result.Errors, vErr)
			}
		}
	}

	// Validate against expected output if provided
	if tr.mockData.ExpectedOutput != nil {
		tr.validateOutput(result)
	}

	return result, nil
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
	case "filter":
		return tr.executeFilter(L)
	case "feature":
		return tr.executeFeature(L)
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

// executeFilter executes a filter callback.
func (tr *TestRunner) executeFilter(L *lua.LState) (*TestResult, error) {
	result := &TestResult{Success: false}

	// Look for nauthilus_call_filter function
	fn := L.GetGlobal("nauthilus_call_filter")
	if fn.Type() != lua.LTFunction {
		return result, fmt.Errorf("nauthilus_call_filter function not found in script")
	}

	// Create request table
	requestTable := tr.createRequestTable(L)

	// Call the filter with request table
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, requestTable); err != nil {
		return result, fmt.Errorf("filter execution failed: %w", err)
	}

	// Get the result (filters return integers)
	ret := L.Get(-1)
	L.Pop(1)

	if ret.Type() == lua.LTNumber {
		filterResult := int(lua.LVAsNumber(ret))
		result.FilterResult = &filterResult
		result.Success = true
	} else {
		return result, fmt.Errorf("filter returned unexpected type: %s", ret.Type())
	}

	return result, nil
}

// executeFeature executes a feature callback.
func (tr *TestRunner) executeFeature(L *lua.LState) (*TestResult, error) {
	result := &TestResult{Success: false}

	// Look for nauthilus_call_feature function
	fn := L.GetGlobal("nauthilus_call_feature")
	if fn.Type() != lua.LTFunction {
		return result, fmt.Errorf("nauthilus_call_feature function not found in script")
	}

	// Create request table
	requestTable := tr.createRequestTable(L)

	// Call the feature with request table
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, requestTable); err != nil {
		return result, fmt.Errorf("feature execution failed: %w", err)
	}

	// Get the result (features return booleans)
	ret := L.Get(-1)
	L.Pop(1)

	if ret.Type() == lua.LTBool {
		featureResult := lua.LVAsBool(ret)
		result.FeatureResult = &featureResult
		result.Success = true
	} else {
		return result, fmt.Errorf("feature returned unexpected type: %s", ret.Type())
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

	// Look for nauthilus_backend_verify_password function
	fn := L.GetGlobal("nauthilus_backend_verify_password")
	if fn.Type() != lua.LTFunction {
		return result, fmt.Errorf("nauthilus_backend_verify_password function not found in script")
	}

	// Create request table
	requestTable := tr.createRequestTable(L)

	// Call the backend with request table
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, requestTable); err != nil {
		return result, fmt.Errorf("backend execution failed: %w", err)
	}

	// Get the result (backends return tables/userdata)
	ret := L.Get(-1)
	L.Pop(1)

	// For backends, we check if it's a table or userdata
	if ret.Type() == lua.LTTable || ret.Type() == lua.LTUserData {
		backendResult := true
		result.BackendResult = &backendResult
		result.Success = true

		switch v := ret.(type) {
		case *lua.LTable:
			authenticatedVal := v.RawGetString(definitions.LuaBackendResultAuthenticated)
			if authenticatedVal.Type() == lua.LTBool {
				authenticated := lua.LVAsBool(authenticatedVal)
				result.BackendAuthenticated = &authenticated
			}

			userFoundVal := v.RawGetString(definitions.LuaBackendResultUserFound)
			if userFoundVal.Type() == lua.LTBool {
				userFound := lua.LVAsBool(userFoundVal)
				result.BackendUserFound = &userFound
			}

			accountFieldVal := v.RawGetString(definitions.LuaBackendResultAccountField)
			if accountFieldVal.Type() == lua.LTString {
				accountField := lua.LVAsString(accountFieldVal)
				result.BackendAccountField = &accountField
			}

			displayNameVal := v.RawGetString(definitions.LuaBackendResultDisplayNameField)
			if displayNameVal.Type() == lua.LTString {
				displayName := lua.LVAsString(displayNameVal)
				result.BackendDisplayName = &displayName
			}

			uniqueUserIDVal := v.RawGetString(definitions.LuaBAckendResultUniqueUserIDField)
			if uniqueUserIDVal.Type() == lua.LTString {
				uniqueUserID := lua.LVAsString(uniqueUserIDVal)
				result.BackendUniqueUserID = &uniqueUserID
			}
		case *lua.LUserData:
			if backendResultObj, ok := v.Value.(*backendResultMockValue); ok && backendResultObj != nil {
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
			}
		}
	} else if ret.Type() == lua.LTNil {
		backendResult := false
		result.BackendResult = &backendResult
		result.Success = false
	} else {
		return result, fmt.Errorf("backend returned unexpected type: %s", ret.Type())
	}

	return result, nil
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

// validateOutput validates the test result against expected output.
func (tr *TestRunner) validateOutput(result *TestResult) {
	expected := tr.mockData.ExpectedOutput

	// Validate filter result
	if expected.FilterResult != nil && result.FilterResult != nil {
		if *expected.FilterResult != *result.FilterResult {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("filter result mismatch: expected %d, got %d",
					*expected.FilterResult, *result.FilterResult))
		}
	}

	// Validate feature result
	if expected.FeatureResult != nil && result.FeatureResult != nil {
		if *expected.FeatureResult != *result.FeatureResult {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("feature result mismatch: expected %t, got %t",
					*expected.FeatureResult, *result.FeatureResult))
		}
	}

	// Validate action result
	if expected.ActionResult != nil && result.ActionResult != nil {
		if *expected.ActionResult != *result.ActionResult {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("action result mismatch: expected %t, got %t",
					*expected.ActionResult, *result.ActionResult))
		}
	}

	// Validate backend result
	if expected.BackendResult != nil && result.BackendResult != nil {
		if *expected.BackendResult != *result.BackendResult {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("backend result mismatch: expected %t, got %t",
					*expected.BackendResult, *result.BackendResult))
		}
	}

	// Validate selected backend address
	if expected.UsedBackendAddress != nil {
		if result.UsedBackendAddress == nil {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("used backend address mismatch: expected %s, got <nil>",
					*expected.UsedBackendAddress))
		} else if *expected.UsedBackendAddress != *result.UsedBackendAddress {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("used backend address mismatch: expected %s, got %s",
					*expected.UsedBackendAddress, *result.UsedBackendAddress))
		}
	}

	if expected.BackendAuthenticated != nil {
		if result.BackendAuthenticated == nil {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("backend authenticated mismatch: expected %t, got <nil>",
					*expected.BackendAuthenticated))
		} else if *expected.BackendAuthenticated != *result.BackendAuthenticated {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("backend authenticated mismatch: expected %t, got %t",
					*expected.BackendAuthenticated, *result.BackendAuthenticated))
		}
	}

	if expected.BackendUserFound != nil {
		if result.BackendUserFound == nil {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("backend user_found mismatch: expected %t, got <nil>",
					*expected.BackendUserFound))
		} else if *expected.BackendUserFound != *result.BackendUserFound {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("backend user_found mismatch: expected %t, got %t",
					*expected.BackendUserFound, *result.BackendUserFound))
		}
	}

	if expected.BackendAccountField != nil {
		if result.BackendAccountField == nil {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("backend account_field mismatch: expected %s, got <nil>",
					*expected.BackendAccountField))
		} else if *expected.BackendAccountField != *result.BackendAccountField {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("backend account_field mismatch: expected %s, got %s",
					*expected.BackendAccountField, *result.BackendAccountField))
		}
	}

	if expected.BackendDisplayName != nil {
		if result.BackendDisplayName == nil {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("backend display_name mismatch: expected %s, got <nil>",
					*expected.BackendDisplayName))
		} else if *expected.BackendDisplayName != *result.BackendDisplayName {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("backend display_name mismatch: expected %s, got %s",
					*expected.BackendDisplayName, *result.BackendDisplayName))
		}
	}

	if expected.BackendUniqueUserID != nil {
		if result.BackendUniqueUserID == nil {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("backend unique_user_id mismatch: expected %s, got <nil>",
					*expected.BackendUniqueUserID))
		} else if *expected.BackendUniqueUserID != *result.BackendUniqueUserID {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("backend unique_user_id mismatch: expected %s, got %s",
					*expected.BackendUniqueUserID, *result.BackendUniqueUserID))
		}
	}

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

	if expected.CacheFlushAccountName != nil {
		if result.CacheFlushAccountName == nil {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("cache flush account name mismatch: expected %s, got <nil>",
					*expected.CacheFlushAccountName))
		} else if *expected.CacheFlushAccountName != *result.CacheFlushAccountName {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("cache flush account name mismatch: expected %s, got %s",
					*expected.CacheFlushAccountName, *result.CacheFlushAccountName))
		}
	}

	// Validate selected backend port
	if expected.UsedBackendPort != nil {
		if result.UsedBackendPort == nil {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("used backend port mismatch: expected %d, got <nil>",
					*expected.UsedBackendPort))
		} else if *expected.UsedBackendPort != *result.UsedBackendPort {
			result.Success = false
			result.Errors = append(result.Errors,
				fmt.Errorf("used backend port mismatch: expected %d, got %d",
					*expected.UsedBackendPort, *result.UsedBackendPort))
		}
	}

	if expected.StatusMessageContain != nil {
		for _, expectedStatus := range expected.StatusMessageContain {
			found := false
			for _, status := range result.StatusMessages {
				if strings.Contains(status, expectedStatus) {
					found = true
					break
				}
			}

			if !found {
				result.Success = false
				result.Errors = append(result.Errors,
					fmt.Errorf("expected status message not found: %s", expectedStatus))
			}
		}
	}

	if expected.StatusMessageNotContain != nil {
		for _, unexpectedStatus := range expected.StatusMessageNotContain {
			for _, status := range result.StatusMessages {
				if strings.Contains(status, unexpectedStatus) {
					result.Success = false
					result.Errors = append(result.Errors,
						fmt.Errorf("unexpected status message found: %s", unexpectedStatus))
					break
				}
			}
		}
	}

	// Validate logs contain expected strings
	if expected.LogsContain != nil {
		for _, expectedLog := range expected.LogsContain {
			found := false
			for _, log := range result.Logs {
				if strings.Contains(log, expectedLog) {
					found = true
					break
				}
			}
			if !found {
				result.Success = false
				result.Errors = append(result.Errors,
					fmt.Errorf("expected log not found: %s", expectedLog))
			}
		}
	}

	// Validate logs don't contain unexpected strings
	if expected.LogsNotContain != nil {
		for _, unexpectedLog := range expected.LogsNotContain {
			for _, log := range result.Logs {
				if strings.Contains(log, unexpectedLog) {
					result.Success = false
					result.Errors = append(result.Errors,
						fmt.Errorf("unexpected log found: %s", unexpectedLog))
					break
				}
			}
		}
	}

	// Check if error was expected
	if expected.ErrorExpected && len(result.Errors) == 0 {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Errorf("expected error but none occurred"))
	} else if !expected.ErrorExpected && len(result.Errors) > 0 {
		result.Success = false
	}
}

// PrintResult prints the test result to stdout.
func (tr *TestRunner) PrintResult(result *TestResult) {
	fmt.Println("\n=== Lua Script Test Results ===")
	fmt.Printf("Script: %s\n", tr.scriptPath)
	fmt.Printf("Callback Type: %s\n", tr.callbackType)
	fmt.Printf("Success: %t\n\n", result.Success)

	if result.FilterResult != nil {
		fmt.Printf("Filter Result: %d\n", *result.FilterResult)
	}
	if result.FeatureResult != nil {
		fmt.Printf("Feature Result: %t\n", *result.FeatureResult)
	}
	if result.ActionResult != nil {
		fmt.Printf("Action Result: %t\n", *result.ActionResult)
	}
	if result.BackendResult != nil {
		fmt.Printf("Backend Result: %t\n", *result.BackendResult)
	}
	if result.BackendAuthenticated != nil {
		fmt.Printf("Backend Authenticated: %t\n", *result.BackendAuthenticated)
	}
	if result.BackendUserFound != nil {
		fmt.Printf("Backend User Found: %t\n", *result.BackendUserFound)
	}
	if result.BackendAccountField != nil {
		fmt.Printf("Backend Account Field: %s\n", *result.BackendAccountField)
	}
	if result.BackendDisplayName != nil {
		fmt.Printf("Backend Display Name: %s\n", *result.BackendDisplayName)
	}
	if result.BackendUniqueUserID != nil {
		fmt.Printf("Backend Unique User ID: %s\n", *result.BackendUniqueUserID)
	}
	if result.UsedBackendAddress != nil {
		fmt.Printf("Used Backend Address: %s\n", *result.UsedBackendAddress)
	}
	if result.UsedBackendPort != nil {
		fmt.Printf("Used Backend Port: %d\n", *result.UsedBackendPort)
	}
	if len(result.CacheFlushAdditionalKeys) > 0 {
		fmt.Printf("Cache Flush Additional Keys: %v\n", result.CacheFlushAdditionalKeys)
	}
	if result.CacheFlushAccountName != nil {
		fmt.Printf("Cache Flush Account Name: %s\n", *result.CacheFlushAccountName)
	}
	if len(result.StatusMessages) > 0 {
		fmt.Println("\nStatus Messages:")
		for _, status := range result.StatusMessages {
			fmt.Printf("  [STATUS] %s\n", status)
		}
	}

	if len(result.Logs) > 0 {
		fmt.Println("\nLogs:")
		for _, log := range result.Logs {
			fmt.Printf("  %s\n", log)
		}
	}

	if len(result.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, err := range result.Errors {
			fmt.Printf("  ✗ %s\n", err)
		}
	}

	fmt.Println("\n===============================")
}

// GetExitCode returns the appropriate exit code based on test result.
func (tr *TestRunner) GetExitCode(result *TestResult) int {
	if result.Success {
		return 0
	}

	return 1
}
