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

package lualib

import (
	"context"
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	lua "github.com/yuin/gopher-lua"
)

// BackendResultManager manages backend result operations for Lua.
type BackendResultManager struct {
	*BaseManager
}

// NewBackendResultManager creates a new BackendResultManager.
func NewBackendResultManager(ctx context.Context, cfg config.File, logger *slog.Logger) *BackendResultManager {
	return &BackendResultManager{
		BaseManager: NewBaseManager(ctx, cfg, logger),
	}
}

// LuaBackendResult holds the response returned by the Lua backend. Information about user authentication, user account,
// and error details are encapsulated in this data structure.
type LuaBackendResult struct {
	// Authenticated represents whether the user is authenticated or not
	Authenticated bool

	// UserFound indicates whether the user was found in the system or not
	UserFound bool

	// AccountField is the field associated with the user's account
	AccountField string

	// TOTPSecretField is the field that holds the user's TOTP Secret
	TOTPSecretField string

	// TOTPRecoveryField is the field for the user's TOTP recovery code
	TOTPRecoveryField string

	// UniqueUserIDField is the unique user id field
	UniqueUserIDField string

	// DisplayNameField is the display name associated with the user's account
	DisplayNameField string

	// WebAuthnCredentials holds a list of serialized WebAuthn credentials (JSON)
	WebAuthnCredentials []string

	// Err captures any error that occurred during the backend process
	Err error

	// Attributes holds any other attributes related to the user's account
	Attributes map[any]any

	// Logs is a pointer to a custom log key-value pair associated with the Lua script.
	Logs *CustomLogKeyValue
}

// New creates a new instance of LuaBackendResult, wraps it in a user data object, and sets its metatable.
func (m *BackendResultManager) New(L *lua.LState) int {
	stack := luastack.NewManager(L)
	backendResult := &LuaBackendResult{}
	userData := L.NewUserData()

	userData.Value = backendResult

	L.SetMetatable(userData, L.GetTypeMetatable(definitions.LuaBackendResultTypeName))

	return stack.PushResult(userData)
}

// checkBackendResult retrieves and validates a LuaBackendResult instance from the Lua state at the given stack index.
func (m *BackendResultManager) checkBackendResult(L *lua.LState) *LuaBackendResult {
	stack := luastack.NewManager(L)

	userData := stack.CheckUserData(1)
	if userData == nil {
		stack.L.ArgError(1, "backend_result expected")

		return nil
	}

	if value, ok := userData.Value.(*LuaBackendResult); ok && value != nil {
		return value
	}

	stack.L.ArgError(1, "backend_result expected")

	return nil
}

// GetSetAuthenticated sets or retrieves the Authenticated field.
func (m *BackendResultManager) GetSetAuthenticated(L *lua.LState) int {
	stack := luastack.NewManager(L)

	backendResult := m.checkBackendResult(L)
	if backendResult == nil {
		return 0
	}

	if stack.GetTop() == 2 {
		backendResult.Authenticated = stack.L.CheckBool(2)

		return 0
	}

	return stack.PushResult(lua.LBool(backendResult.Authenticated))
}

// GetSetUserFound sets or returns the value of the UserFound field.
func (m *BackendResultManager) GetSetUserFound(L *lua.LState) int {
	stack := luastack.NewManager(L)

	backendResult := m.checkBackendResult(L)
	if backendResult == nil {
		return 0
	}

	if stack.GetTop() == 2 {
		backendResult.UserFound = stack.L.CheckBool(2)

		return 0
	}

	return stack.PushResult(lua.LBool(backendResult.UserFound))
}

// GetSetAccountField sets or returns the value of the AccountField field.
func (m *BackendResultManager) GetSetAccountField(L *lua.LState) int {
	stack := luastack.NewManager(L)

	backendResult := m.checkBackendResult(L)
	if backendResult == nil {
		return 0
	}

	if stack.GetTop() == 2 {
		backendResult.AccountField = stack.CheckString(2)

		return 0
	}

	return stack.PushResult(lua.LString(backendResult.AccountField))
}

// GetSetTOTPSecretField sets or returns the value of the TOTPSecretField field.
func (m *BackendResultManager) GetSetTOTPSecretField(L *lua.LState) int {
	stack := luastack.NewManager(L)

	backendResult := m.checkBackendResult(L)
	if backendResult == nil {
		return 0
	}

	if stack.GetTop() == 2 {
		backendResult.TOTPSecretField = stack.CheckString(2)

		return 0
	}

	return stack.PushResult(lua.LString(backendResult.TOTPSecretField))
}

// GetSetTOTPRecoveryField sets or returns the value of the TOTPRecoveryField field.
func (m *BackendResultManager) GetSetTOTPRecoveryField(L *lua.LState) int {
	stack := luastack.NewManager(L)

	backendResult := m.checkBackendResult(L)
	if backendResult == nil {
		return 0
	}

	if stack.GetTop() == 2 {
		backendResult.TOTPRecoveryField = stack.CheckString(2)

		return 0
	}

	return stack.PushResult(lua.LString(backendResult.TOTPRecoveryField))
}

// GetSetUniqueUserIDField sets or returns the value of the UniqueUserIDField field.
func (m *BackendResultManager) GetSetUniqueUserIDField(L *lua.LState) int {
	stack := luastack.NewManager(L)

	backendResult := m.checkBackendResult(L)
	if backendResult == nil {
		return 0
	}

	if stack.GetTop() == 2 {
		backendResult.UniqueUserIDField = stack.CheckString(2)

		return 0
	}

	return stack.PushResult(lua.LString(backendResult.UniqueUserIDField))
}

// GetSetDisplayNameField sets or returns the value of the DisplayNameField field.
func (m *BackendResultManager) GetSetDisplayNameField(L *lua.LState) int {
	stack := luastack.NewManager(L)

	backendResult := m.checkBackendResult(L)
	if backendResult == nil {
		return 0
	}

	if stack.GetTop() == 2 {
		backendResult.DisplayNameField = stack.CheckString(2)

		return 0
	}

	return stack.PushResult(lua.LString(backendResult.DisplayNameField))
}

// GetSetWebAuthnCredentials sets or retrieves the WebAuthnCredentials field.
func (m *BackendResultManager) GetSetWebAuthnCredentials(L *lua.LState) int {
	stack := luastack.NewManager(L)

	backendResult := m.checkBackendResult(L)
	if backendResult == nil {
		return 0
	}

	if stack.GetTop() == 2 {
		table := stack.CheckTable(2)
		var credentials []string
		table.ForEach(func(_, v lua.LValue) {
			if str, ok := v.(lua.LString); ok {
				credentials = append(credentials, string(str))
			}
		})
		backendResult.WebAuthnCredentials = credentials

		return 0
	}

	table := L.NewTable()
	for _, cred := range backendResult.WebAuthnCredentials {
		table.Append(lua.LString(cred))
	}

	return stack.PushResult(table)
}

// GetSetAttributes sets or retrieves the Attributes field.
func (m *BackendResultManager) GetSetAttributes(L *lua.LState) int {
	stack := luastack.NewManager(L)

	backendResult := m.checkBackendResult(L)
	if backendResult == nil {
		return 0
	}

	if stack.GetTop() == 2 {
		attributes := convert.LuaValueToGo(stack.CheckTable(2)).(map[any]any)
		backendResult.Attributes = attributes

		return 0
	}

	return stack.PushResult(convert.GoToLuaValue(L, backendResult.Attributes))
}

// LoaderModBackendResult initializes and loads the backend result module for Lua.
func LoaderModBackendResult(ctx context.Context, cfg config.File, logger *slog.Logger) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewBackendResultManager(ctx, cfg, logger)

		// Register methods
		mt := L.NewTypeMetatable(definitions.LuaBackendResultTypeName)

		L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaBackendResultAuthenticated:       manager.GetSetAuthenticated,
			definitions.LuaBackendResultUserFound:           manager.GetSetUserFound,
			definitions.LuaBackendResultAccountField:        manager.GetSetAccountField,
			definitions.LuaBackendResultTOTPSecretField:     manager.GetSetTOTPSecretField,
			definitions.LuaBackendResultTOTPRecoveryField:   manager.GetSetTOTPRecoveryField,
			definitions.LuaBAckendResultUniqueUserIDField:   manager.GetSetUniqueUserIDField,
			definitions.LuaBackendResultDisplayNameField:    manager.GetSetDisplayNameField,
			definitions.LuaBackendResultWebAuthnCredentials: manager.GetSetWebAuthnCredentials,
			definitions.LuaBackendResultAttributes:          manager.GetSetAttributes,
		}))

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"new": manager.New,
		})

		return stack.PushResult(mod)
	}
}
