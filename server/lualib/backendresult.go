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
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	lua "github.com/yuin/gopher-lua"
)

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

	// Err captures any error that occurred during the backend process
	Err error

	// Attributes holds any other attributes related to the user's account
	Attributes map[any]any

	// Logs is a pointer to a custom log key-value pair associated with the Lua script.
	Logs *CustomLogKeyValue
}

// RegisterBackendResultType registers a new Lua type `nauthilus_backend_result` and attaches provided methods to its metatable.
func RegisterBackendResultType(L *lua.LState, methods ...string) {
	mt := L.NewTypeMetatable(definitions.LuaBackendResultTypeName)

	L.SetGlobal(definitions.LuaBackendResultTypeName, mt)

	// Static attributes
	L.SetField(mt, "new", L.NewFunction(newBackendResult))

	usedBackendResultMethods := make(map[string]lua.LGFunction)

	for _, method := range methods {
		usedBackendResultMethods[method] = backendResultMethods[method]
	}

	// Methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), usedBackendResultMethods))
}

// newBackendResult creates a new instance of LuaBackendResult, wraps it in a user data object, and sets its metatable.
func newBackendResult(L *lua.LState) int {
	backendResult := &LuaBackendResult{}
	userData := L.NewUserData()

	userData.Value = backendResult

	L.SetMetatable(userData, L.GetTypeMetatable(definitions.LuaBackendResultTypeName))
	L.Push(userData)

	return 1
}

// checkBackendResult retrieves and validates a LuaBackendResult instance from the Lua state at the given stack index.
// Returns the LuaBackendResult instance or raises a Lua argument error if the type is invalid.
func checkBackendResult(L *lua.LState) *LuaBackendResult {
	userData := L.CheckUserData(1)

	if value, ok := userData.Value.(*LuaBackendResult); ok {
		return value
	}

	L.ArgError(1, "backend_result expected")

	return nil
}

// backendResultMethods is a map that holds the names of backend result methods and their corresponding functions.
var backendResultMethods = map[string]lua.LGFunction{
	definitions.LuaBackendResultAuthenticated:     backendResultGetSetAuthenticated,
	definitions.LuaBackendResultUserFound:         backendResultGetSetUserFound,
	definitions.LuaBackendResultAccountField:      backendResultGetSetAccountField,
	definitions.LuaBackendResultTOTPSecretField:   backendResultGetSetTOTPSecretField,
	definitions.LuaBackendResultTOTPRecoveryField: backendResultGetSetTOTPRecoveryField,
	definitions.LuaBAckendResultUniqueUserIDField: backendResultGetSetUniqueUserIDField,
	definitions.LuaBackendResultDisplayNameField:  backendResultGetSetDisplayNameField,
	definitions.LuaBackendResultAttributes:        backendResultGetSetAttributes,
}

// backendResultGetSetAuthenticated sets or retrieves the Authenticated field in the LuaBackendResult struct.
// When called with a boolean argument, it sets the Authenticated field to the provided value.
// When called without an argument, it returns the current value of the Authenticated field.
func backendResultGetSetAuthenticated(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.Authenticated = L.CheckBool(2)

		return 0
	}

	L.Push(lua.LBool(backendResult.Authenticated))

	return 1
}

// backendResultGetSetUserFound sets or returns the value of the UserFound field in the backendResult
// struct. If called with a boolean argument, it sets the UserFound field to the provided value.
// If called without any argument, it returns the current value of the UserFound field.
func backendResultGetSetUserFound(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.UserFound = L.CheckBool(2)

		return 0
	}

	L.Push(lua.LBool(backendResult.UserFound))

	return 1
}

// backendResultGetSetAccountField sets or returns the value of the AccountField field in the backendResult
// struct. If called with a string argument, it sets the AccountField field to the provided value.
// If called without any argument, it returns the current value of the AccountField field.
func backendResultGetSetAccountField(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.AccountField = L.CheckString(2)

		return 0
	}

	L.Push(lua.LString(backendResult.AccountField))

	return 1
}

// backendResultGetSetTOTPSecretField sets or returns the value of the TOTPSecretField field in the backendResult struct.
// If called with a string argument, it sets the TOTPSecretField field to the provided value.
// If called without any argument, it returns the current value of the TOTPSecretField field.
func backendResultGetSetTOTPSecretField(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.TOTPSecretField = L.CheckString(2)

		return 0
	}

	L.Push(lua.LString(backendResult.TOTPSecretField))

	return 1
}

// backendResultGetSetTOTPRecoveryField sets or returns the value of the TOTPRecoveryField field in the backendResult struct.
// If called with a string argument, it sets the TOTPRecoveryField field to the provided value.
// If called without any argument, it returns the current value of the TOTPRecoveryField field.
func backendResultGetSetTOTPRecoveryField(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.TOTPRecoveryField = L.CheckString(2)

		return 0
	}

	L.Push(lua.LString(backendResult.TOTPRecoveryField))

	return 1
}

// backendResultGetSetUniqueUserIDField sets or returns the value of the UniqueUserIDField field in the backendResult struct.
// If called with a string argument, it sets the UniqueUserIDField field to the provided value.
// If called without any argument, it returns the current value of the UniqueUserIDField field.
func backendResultGetSetUniqueUserIDField(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.UniqueUserIDField = L.CheckString(2)

		return 0
	}

	L.Push(lua.LString(backendResult.UniqueUserIDField))

	return 1
}

// backendResultGetSetDisplayNameField sets or returns the value of the DisplayNameField field in the backendResult
// struct. If called with a string argument, it sets the DisplayNameField field to the provided value.
// If called without any argument, it returns the current value of the DisplayNameField field.
func backendResultGetSetDisplayNameField(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		backendResult.DisplayNameField = L.CheckString(2)

		return 0
	}

	L.Push(lua.LString(backendResult.DisplayNameField))

	return 1
}

// backendResultGetSetAttributes sets or retrieves the SearchAttributes field of the LuaBackendResult struct as a Lua table.
// If called with a table argument, it updates the SearchAttributes field with the provided key-value pairs.
// If called without arguments, it returns the current SearchAttributes field as a Lua table.
func backendResultGetSetAttributes(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		attributes := convert.LuaValueToGo(L.CheckTable(2)).(map[any]any)
		backendResult.Attributes = attributes

		return 0
	}

	L.Push(convert.GoToLuaValue(L, backendResult.Attributes))

	return 1
}
