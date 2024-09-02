package lualib

import (
	"sync"

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/yuin/gopher-lua"
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

// LuaBackendResultStatePool embeds the LuaStatePool type.
// It provides methods for retrieving, returning, and shutting down Lua states.
type LuaBackendResultStatePool struct {
	*LuaStatePool
}

// NewLuaBackendResultStatePool creates a new instance of LuaBackendResultStatePool that implements the LuaBaseStatePool
// interface. It initializes a LuaStatePool with a New function
func NewLuaBackendResultStatePool(methods ...string) LuaBaseStatePool {
	lp := &LuaStatePool{
		New: func() *lua.LState {
			L := NewLStateWithDefaultLibraries()

			registerBackendResultType(L, methods...)

			return L
		},
		MaxStates: global.MaxLuaStatePoolSize,
	}

	lp.Cond = sync.Cond{L: &lp.Mu}

	return &LuaBackendResultStatePool{lp.InitializeStatePool()}
}

// registerBackendResultType registers the Lua type "backend_result" in the given Lua state.
// It sets the type metatable with the given name and creates the necessary static attributes and methods.
func registerBackendResultType(L *lua.LState, methods ...string) {
	mt := L.NewTypeMetatable(global.LuaBackendResultTypeName)

	L.SetGlobal(global.LuaBackendResultTypeName, mt)

	// Static attributes
	L.SetField(mt, "new", L.NewFunction(newBackendResult))

	usedBackendResultMethods := make(map[string]lua.LGFunction)

	for _, method := range methods {
		usedBackendResultMethods[method] = backendResultMethods[method]
	}

	// Methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), usedBackendResultMethods))
}

// newBackendResult is a function for creating a new instance of LuaBackendResult
// and returning it as a userdata type in Lua. This function is designed to be
// callable from a Lua context, hence the L *lua.LState input parameter, which
// provides the necessary Lua environment for the function execution.
// The int return value is standard for functions to be called from Lua,
// indicating the number of results that the function is returning to the Lua stack.
func newBackendResult(L *lua.LState) int {
	backendResult := &LuaBackendResult{}
	userData := L.NewUserData()

	userData.Value = backendResult

	L.SetMetatable(userData, L.GetTypeMetatable(global.LuaBackendResultTypeName))
	L.Push(userData)

	return 1
}

// checkBackendResult checks if the argument at index 1 in the Lua state is of a type *LuaBackendResult,
// if it is, returns its value; otherwise, it raises an error indicating that "backend_result" was expected, and returns nil.
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
	global.LuaBackendResultAuthenticated:     backendResultGetSetAuthenticated,
	global.LuaBackendResultUserFound:         backendResultGetSetUserFound,
	global.LuaBackendResultAccountField:      backendResultGetSetAccountField,
	global.LuaBackendResultTOTPSecretField:   backendResultGetSetTOTPSecretField,
	global.LuaBackendResultTOTPRecoveryField: backendResultGetSetTOTPRecoveryField,
	global.LuaBAckendResultUniqueUserIDField: backendResultGetSetUniqueUserIDField,
	global.LuaBackendResultDisplayNameField:  backendResultGetSetDisplayNameField,
	global.LuaBackendResultAttributes:        backendResultGetSetAttributes,
}

// backendResultGetSetAuthenticated sets or returns the value of the Authenticated field in the backendResult
// struct. If called with a boolean argument, it sets the Authenticated field to the provided value.
// If called without any argument, it returns the current value of the Authenticated field.
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

// backendResultGetSetAttributes retrieves or sets the value of the 'Attributes' field in the 'backendResult'
// struct. If called with a lua.LTable argument, it sets the 'Attributes' field to the mapped table representation
// of the provided lua.LTable Input.
//
// If called without any argument, it returns the current value of the 'Attributes' field.
//
// Note: The 'Attributes' field holds any other attributes related to the user's account.
func backendResultGetSetAttributes(L *lua.LState) int {
	backendResult := checkBackendResult(L)

	if L.GetTop() == 2 {
		// XXX: We expect keys to be strings!
		backendResult.Attributes = convert.LuaTableToMap(L.CheckTable(2))

		return 0
	}

	L.Push(convert.MapToLuaTable(L, backendResult.Attributes))

	return 1
}
