package lualib

import (
	"fmt"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/go-kit/log/level"
	lua "github.com/yuin/gopher-lua"
)

// Context is a system-wide Lua context designed to exchange Lua LValues between all Lua levels. Even it implements all
// methodes from Context, its use is limitted to data exchange. It can not be used to abort running threads. Usage of
// this context is thread safe.
type Context struct {
	data map[any]any
	mu   sync.RWMutex
}

// NewContext initializes a new Lua Context.
func NewContext() *Context {
	ctx := &Context{}
	ctx.data = make(map[any]any)

	return ctx
}

// Set sets or replaces a new key/value pair in the Lua Context map.
func (c *Context) Set(key any, value any) {
	if c == nil {
		return
	}

	c.mu.Lock()

	c.data[key] = value

	c.mu.Unlock()
}

// Get returns the lua.LValue value aquired by key from the Lua Context. If no key was found, it returns nil.
func (c *Context) Get(key any) any {
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
func (c *Context) Delete(key lua.LValue) {
	if c == nil {
		return
	}

	c.mu.Lock()

	switch mappedKey := key.(type) {
	case lua.LString:
		delete(c.data, string(mappedKey))
	case lua.LBool:
		delete(c.data, bool(mappedKey))
	case lua.LNumber:
		delete(c.data, float64(mappedKey))
	default:
		level.Warn(logging.DefaultLogger).Log(
			global.LogKeyWarning, fmt.Sprintf("Lua key '%v' unsupported", mappedKey))
	}

	c.mu.Unlock()
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
		key := L.Get(1)

		switch value := L.Get(2).(type) {
		case lua.LString:
			ctx.Set(key, string(value))
		case lua.LBool:
			ctx.Set(key, bool(value))
		case lua.LNumber:
			ctx.Set(key, float64(value))
		case *lua.LTable:
			ctx.Set(key, LuaTableToMap(value))
		default:
			level.Warn(logging.DefaultLogger).Log(
				global.LogKeyWarning, fmt.Sprintf("Lua key='%v' value='%v' unsupported", key, value))
		}

		return 0
	}
}

// ContextGet is a wrapper function to Context.Get(...). The argument ctx provides the Lua context for the underlying
// Lua function.
func ContextGet(ctx *Context) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.Get(1)

		switch value := ctx.Get(key).(type) {
		case string:
			L.Push(lua.LString(value))
		case bool:
			L.Push(lua.LBool(value))
		case float64:
			L.Push(lua.LNumber(value))
		case map[any]any:
			L.Push(MapToLuaTable(L, value))
		case nil:
			L.Push(lua.LNil)
		default:
			level.Warn(logging.DefaultLogger).Log(
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
		key := L.Get(1)

		ctx.Delete(key)

		return 0
	}
}
