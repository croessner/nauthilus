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

package lualib

import (
	"context"
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	lua "github.com/yuin/gopher-lua"
)

// BaseManager provides common fields for all Lua module managers.
type BaseManager struct {
	Ctx    context.Context
	Cfg    config.File
	Logger *slog.Logger
}

// NewBaseManager creates a new BaseManager.
func NewBaseManager(ctx context.Context, cfg config.File, logger *slog.Logger) *BaseManager {
	return &BaseManager{
		Ctx:    ctx,
		Cfg:    cfg,
		Logger: logger,
	}
}

// getNumberFromTable retrieves an integer value from a Lua table by its key. Defaults to 0 if the key is non-existent or invalid.
func getNumberFromTable(table *lua.LTable, key string) int {
	value := table.RawGetString(key)

	if value == lua.LNil {
		return 0
	}

	return int(lua.LVAsNumber(value))
}

// getStringFromTable retrieves a string value from a Lua table by its key. Defaults to an empty string if the key is non-existent.
func getStringFromTable(table *lua.LTable, key string) string {
	value := table.RawGetString(key)

	if value == lua.LNil {
		return ""
	}

	return value.String()
}

// getBoolFromTable retrieves a boolean value from a Lua table by its key. Defaults to false if the key is non-existent.
func getBoolFromTable(table *lua.LTable, key string) bool {
	value := table.RawGetString(key)

	if value == lua.LNil {
		return false
	}

	return lua.LVAsBool(value)
}
