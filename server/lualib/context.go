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
	"reflect"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	lua "github.com/yuin/gopher-lua"
)

// ContextManager manages Lua context operations.
type ContextManager struct{}

// NewContextManager creates a new ContextManager.
func NewContextManager() *ContextManager {
	return &ContextManager{}
}

func (m *ContextManager) currentContext(L *lua.LState) *Context {
	return RequireLuaContext(L)
}

// ContextSet is a wrapper function to Context.Set(...).
func (m *ContextManager) ContextSet(L *lua.LState) int {
	stack := luastack.NewManager(L)
	key := stack.CheckString(1)
	value := stack.CheckAny(2)

	if luaCtx := m.currentContext(L); luaCtx != nil {
		luaCtx.Set(key, convert.LuaValueToGo(value))
	}

	return 0
}

// ContextGet is a wrapper function to Context.Get(...).
func (m *ContextManager) ContextGet(L *lua.LState) int {
	stack := luastack.NewManager(L)
	key := stack.CheckString(1)
	var value any

	if luaCtx := m.currentContext(L); luaCtx != nil {
		value = luaCtx.Get(key)
	}

	return stack.PushResult(convert.GoToLuaValue(L, value))
}

// ContextDelete is a wrapper function to Context.Delete(...).
func (m *ContextManager) ContextDelete(L *lua.LState) int {
	stack := luastack.NewManager(L)
	key := stack.CheckString(1)

	if luaCtx := m.currentContext(L); luaCtx != nil {
		luaCtx.Delete(key)
	}

	return 0
}

// LoaderModContext initializes and loads the context module for Lua.
func LoaderModContext(luaCtx *Context) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewContextManager()

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnCtxSet:    manager.ContextSet,
			definitions.LuaFnCtxGet:    manager.ContextGet,
			definitions.LuaFnCtxDelete: manager.ContextDelete,
		})

		if luaCtx != nil {
			bindRequestValue(L, mod, luaRequestContextKey, luaCtx)
		}

		return stack.PushResult(mod)
	}
}

// LoaderContextStateless returns an empty, stateless module table for nauthilus_context.
// It is intended to be preloaded once per VM (base environment). Per-request bindings will later
// clone this table and inject bound functions via WithCtx factories.
func LoaderContextStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)

		return stack.PushResult(L.NewTable())
	}
}

// Context is a system-wide Lua context designed to exchange Lua LValues between all Lua levels. Even it implements all
// methodes from Context, its use is limitted to data exchange. It can not be used to abort running threads. Usage of
// this context is thread safe.
type Context struct {
	data map[string]any
	mu   sync.RWMutex
}

// ContextDelta describes request-local Lua context changes made by one script.
type ContextDelta struct {
	Set    map[string]any
	Delete []string
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

// Snapshot returns a shallowly typed but recursively copied view of all context values.
func (c *Context) Snapshot() map[string]any {
	if c == nil {
		return map[string]any{}
	}

	c.mu.RLock()

	defer c.mu.RUnlock()

	snapshot := make(map[string]any, len(c.data))
	for key, value := range c.data {
		snapshot[key] = cloneContextValue(value)
	}

	return snapshot
}

// Clone returns an independent context copy for isolated script execution.
func (c *Context) Clone() *Context {
	clone := NewContext()

	for key, value := range c.Snapshot() {
		clone.data[key] = value
	}

	return clone
}

// Diff computes changes between a previous snapshot and the current context state.
func (c *Context) Diff(before map[string]any) ContextDelta {
	after := c.Snapshot()
	delta := ContextDelta{
		Set:    make(map[string]any),
		Delete: make([]string, 0),
	}

	for key, beforeValue := range before {
		afterValue, exists := after[key]
		if !exists {
			delta.Delete = append(delta.Delete, key)

			continue
		}

		if !reflect.DeepEqual(beforeValue, afterValue) {
			delta.Set[key] = afterValue
		}
	}

	for key, afterValue := range after {
		if _, exists := before[key]; !exists {
			delta.Set[key] = afterValue
		}
	}

	return delta
}

// ApplyDelta merges a script delta into the shared request context.
func (c *Context) ApplyDelta(delta ContextDelta) {
	if c == nil {
		return
	}

	c.mu.Lock()

	defer c.mu.Unlock()

	for _, key := range delta.Delete {
		delete(c.data, key)
	}

	for key, value := range delta.Set {
		c.data[key] = cloneContextValue(value)
	}
}

// GetExists retrieves the value associated with the given key and returns a boolean indicating its existence in the context.
func (c *Context) GetExists(key string) (any, bool) {
	if c == nil {
		return nil, false
	}

	c.mu.RLock()

	defer c.mu.RUnlock()

	if value, assertOk := c.data[key]; assertOk {
		return value, true
	}

	return nil, false
}

// Get returns the lua.LValue value aquired by key from the Lua Context. If no key was found, it returns nil.
func (c *Context) Get(key string) any {
	if c == nil {
		return nil
	}

	value, exists := c.GetExists(key)
	if exists {
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

func cloneContextValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		clone := make(map[string]any, len(typed))
		for key, nested := range typed {
			clone[key] = cloneContextValue(nested)
		}

		return clone
	case map[any]any:
		clone := make(map[any]any, len(typed))
		for key, nested := range typed {
			clone[cloneContextValue(key)] = cloneContextValue(nested)
		}

		return clone
	case []any:
		clone := make([]any, len(typed))
		for index, nested := range typed {
			clone[index] = cloneContextValue(nested)
		}

		return clone
	case []string:
		return append([]string(nil), typed...)
	default:
		return value
	}
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
