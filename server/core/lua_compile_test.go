// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"os"

	"github.com/croessner/nauthilus/v4/server/lualib"
	lua "github.com/yuin/gopher-lua"
)

// compileLuaTestFile compiles one test-owned fixture after its explicit filesystem read.
func compileLuaTestFile(path string) (*lua.FunctionProto, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return lualib.CompileLuaSource(path, source)
}
