// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"bytes"
	"fmt"

	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
)

// requireAuthnLuaEntryPoint rejects a callback script that cannot define its entry point.
//
// Candidate preparation never executes a callback: module-level code may write to Redis, open connections, or
// read request state, and it runs with every request anyway. The only load-time check besides compilation is that
// the entry-point name occurs in the script or in a module captured with the candidate. That catches a script
// configured for the wrong stage; whether the entry point is really defined is decided when a request runs it.
func requireAuthnLuaEntryPoint(source []byte, modules *luaseal.Modules, callback string) error {
	if bytes.Contains(source, []byte(callback)) || modules.Mentions(callback) {
		return nil
	}

	return fmt.Errorf("required callback %s is unavailable", callback)
}
