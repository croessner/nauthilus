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
	"fmt"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/go-kit/log/level"
	lua "github.com/yuin/gopher-lua"
)

func LoaderModContext(ctx *Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			global.LuaFnCtxSet:    ContextSet(ctx),
			global.LuaFnCtxGet:    ContextGet(ctx),
			global.LuaFnCtxDelete: ContextDelete(ctx),
		})

		L.Push(mod)

		return 1
	}
}

// Context is a system-wide Lua context designed to exchange Lua LValues between all Lua levels. Even it implements all
// methodes from Context, its use is limitted to data exchange. It can not be used to abort running threads. Usage of
// this context is thread safe.
type Context struct {
	data map[string]any
	mu   sync.RWMutex
}

// NewContext initializes a new Lua Context.
func NewContext() *Context {
	ctx := &Context{}
	ctx.data = make(map[string]any)

	return ctx
}

// Set sets or replaces a new key/value pair in the Lua Context map.
func (c *Context) Set(key string, value any) {
	if c == nil {
		return
	}

	c.mu.Lock()

	c.data[key] = value

	c.mu.Unlock()
}

// Get returns the lua.LValue value aquired by key from the Lua Context. If no key was found, it returns nil.
func (c *Context) Get(key string) any {
	if c == nil {
		return nil
	}

	c.mu.RLock()

	defer c.mu.RUnlock()

	if value, assertOk := c.data[key]; assertOk {
		return value
	}

	return nil
}

// Delete removes a key and its value from the Lua Context.
func (c *Context) Delete(key string) {
	if c == nil {
		return
	}

	c.mu.Lock()

	defer c.mu.Unlock()

	delete(c.data, key)
}

// Deadline is not currently used
func (c *Context) Deadline() (deadline time.Time, ok bool) {
	return
}

// Done is not currently used
func (c *Context) Done() <-chan struct{} {
	return nil
}

// Err is not currently used
func (c *Context) Err() error {
	return nil
}

// Value not currently used
func (c *Context) Value(_ any) lua.LValue {
	return lua.LNil
}

// ContextSet is a wrapper function to Context.Set(...). The argument ctx provides the Lua context for the underlying
// Lua function.
func ContextSet(ctx *Context) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)

		switch value := L.Get(2).(type) {
		case lua.LString:
			ctx.Set(key, string(value))
		case lua.LBool:
			ctx.Set(key, bool(value))
		case lua.LNumber:
			ctx.Set(key, float64(value))
		case *lua.LTable:
			ctx.Set(key, convert.LuaTableToMap(value))
		default:
			level.Warn(log.Logger).Log(
				global.LogKeyWarning, fmt.Sprintf("Lua key='%v' value='%v' unsupported", key, value))
		}

		return 0
	}
}

// ContextGet is a wrapper function to Context.Get(...). The argument ctx provides the Lua context for the underlying
// Lua function.
func ContextGet(ctx *Context) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)

		switch value := ctx.Get(key).(type) {
		case string:
			L.Push(lua.LString(value))
		case bool:
			L.Push(lua.LBool(value))
		case float64:
			L.Push(lua.LNumber(value))
		case map[any]any:
			L.Push(convert.MapToLuaTable(L, value))
		case nil:
			L.Push(lua.LNil)
		default:
			level.Warn(log.Logger).Log(
				global.LogKeyWarning, fmt.Sprintf("Lua key='%v' value='%v' unsupported", key, value))
			L.Push(lua.LNil)
		}

		return 1
	}
}

// ContextDelete is a wrapper function to Context.Delete(...). The argument ctx provides the Lua context for the underlying
// Lua function.
func ContextDelete(ctx *Context) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)

		ctx.Delete(key)

		return 0
	}
}
