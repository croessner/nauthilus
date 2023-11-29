package lualib

import (
	"sync"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// Context is a system wide Lua context designed to exchange Lua LValues between all Lua levels. Even it implements all
// methodes from Context, its use is limitted to data exchange. It can not be used to abort running threads. Usage of
// this context is thread safe.
type Context struct {
	data map[string]lua.LValue
	mu   sync.RWMutex
}

// NewContext initializes a new Lua Context.
func NewContext() *Context {
	ctx := &Context{}
	ctx.data = make(map[string]lua.LValue)

	return ctx
}

// Set sets or replaces a new key/value pair in the Lua Context map.
func (c *Context) Set(key string, value lua.LValue) {
	if c == nil {
		return
	}

	c.mu.Lock()

	c.data[key] = value

	c.mu.Unlock()
}

// Get returns the lua.LValue value aquired by key from the Lua Context. If no key was found, it returns nil.
func (c *Context) Get(key string) lua.LValue {
	if c == nil {
		return lua.LNil
	}

	c.mu.RLock()

	defer c.mu.RUnlock()

	if value, assertOk := c.data[key]; assertOk {
		return value
	}

	return lua.LNil
}

// Delete removes a key and its value from the Lua Context.
func (c *Context) Delete(key string) {
	if c == nil {
		return
	}

	c.mu.Lock()

	delete(c.data, key)

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

// Value implements the context.Context Value() method and is currently a mapper to the Get(...) method
func (c *Context) Value(key any) lua.LValue {
	switch k := key.(type) {
	case string:
		return c.Get(k)
	}

	return lua.LNil
}

// ContextSet is a wrapper function to Context.Set(...). The argument ctx provides the Lua context for the underlying
// Lua function.
func ContextSet(ctx *Context) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)
		value := L.Get(2)

		ctx.Set(key, value)

		return 0
	}
}

// ContextGet is a wrapper function to Context.Get(...). The argument ctx provides the Lua context for the underlying
// Lua function.
func ContextGet(ctx *Context) lua.LGFunction {
	return func(L *lua.LState) int {
		key := L.CheckString(1)
		value := ctx.Get(key)

		L.Push(value)

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
