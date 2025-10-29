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

package bktype

import (
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
)

// LuaRequest is a subset from the Authentication struct.
// LuaRequest is a struct that includes various information for a request to Lua.
type LuaRequest struct {
	// Function is the Lua command that will be executed.
	Function definitions.LuaCommand

	// BackendName is the logical Lua backend name this request must be processed by.
	BackendName string

	// TOTPSecret is the secret value used in time-based one-time password (TOTP) authentication.
	TOTPSecret string

	// Service is the specific service requested by the client.
	Service string

	// Protocol points to the protocol that was used by a client to make the request.
	Protocol *config.Protocol

	// Logs points to custom log key-value pairs to help track the request.
	Logs *lualib.CustomLogKeyValue

	// Context provides context for the Lua command request.
	*lualib.Context

	*lualib.CommonRequest

	// HTTPClientRequest represents the HTTP request object associated with the client's request.
	HTTPClientRequest *http.Request

	// LuaReplyChan is a channel to receive the response from the Lua backend.
	LuaReplyChan chan *lualib.LuaBackendResult
}
