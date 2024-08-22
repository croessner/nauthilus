package lualib

import (
	"github.com/croessner/nauthilus/server/monitoring"
	lua "github.com/yuin/gopher-lua"
)

// CheckBackendConnection is a Lua function that checks the connection to a backend server.
// It receives the server IP address, port number, a boolean flag indicating whether the server runs with HAProxy V2 protocol,
// and a boolean flag indicating whether TLS should be used.
// The function calls the CheckBackendConnection method of the provided monitoring.Monitor instance
// and returns an error message if there is an error, or nil if the connection is successful.
//
// Params:
//   - monitor monitoring.Monitor : The monitoring.Monitor instance used to check the backend connection.
//
// Returns:
//   - int : The number of return values pushed to the Lua stack, always 1.
//
// Lua stack requirements:
//   - 4 arguments are expected in the following order:
//     1. string : The server IP address.
//     2. int : The server port number.
//     3. boolean : Whether the server runs with HAProxy V2 protocol.
//     4. boolean : Whether TLS should be used.
//   - The arguments should be of the expected types; otherwise, an error will be raised.
//   - The function expects to have 1 return value on the stack - nil if the connection is successful,
//     or a string with an error message if there is an error.
//
// Example:
//
//	connection_error = check_backend_connection("192.168.0.1", 8080, false, true)
//	if connection_error ~= nil then
//	    log("Connection failed: " .. connection_error)
//	else
//	    log("Connection successful")
//	end
//
// Note: The above example is in Lua language and should be executed in a Lua environment.
func CheckBackendConnection(monitor monitoring.Monitor) lua.LGFunction {
	return func(L *lua.LState) int {
		if L.GetTop() != 4 {
			L.RaiseError("Invalid number of arguments. Expected 4, got %d", L.GetTop())

			return 0
		}

		server := L.CheckString(1)
		port := L.CheckInt(2)
		haproxyV2 := L.CheckBool(3)
		tls := L.CheckBool(4)

		if err := monitor.CheckBackendConnection(server, port, haproxyV2, tls); err != nil {
			L.Push(lua.LString(err.Error()))

			return 1
		}

		L.Push(lua.LNil)

		return 1
	}
}
