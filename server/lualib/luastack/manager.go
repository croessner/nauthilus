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

package luastack

import (
	lua "github.com/yuin/gopher-lua"
)

// Manager wraps a lua.LState and provides utility methods for interacting with the Lua stack.
type Manager struct {
	L *lua.LState
}

// NewManager creates a new Manager instance.
func NewManager(L *lua.LState) *Manager {
	return &Manager{L: L}
}

// CheckString returns the string at the given stack index or throws a Lua error if the value is not a string.
func (m *Manager) CheckString(n int) string {
	return m.L.CheckString(n)
}

// CheckInt returns the integer at the given stack index or throws a Lua error if the value is not a number.
func (m *Manager) CheckInt(n int) int {
	return m.L.CheckInt(n)
}

// CheckNumber returns the number at the given stack index or throws a Lua error if the value is not a number.
func (m *Manager) CheckNumber(n int) lua.LNumber {
	return m.L.CheckNumber(n)
}

// CheckTable returns the table at the given stack index or throws a Lua error if the value is not a table.
func (m *Manager) CheckTable(n int) *lua.LTable {
	return m.L.CheckTable(n)
}

// CheckAny returns the value at the given stack index.
func (m *Manager) CheckAny(n int) lua.LValue {
	return m.L.CheckAny(n)
}

// OptString returns the string at the given stack index, or the default value if the index is out of range or the value is nil.
func (m *Manager) OptString(n int, def string) string {
	return m.L.OptString(n, def)
}

// OptNumber returns the number at the given stack index, or the default value if the index is out of range or the value is nil.
func (m *Manager) OptNumber(n int, def lua.LNumber) lua.LNumber {
	return m.L.OptNumber(n, def)
}

// GetTop returns the index of the top element in the stack.
func (m *Manager) GetTop() int {
	return m.L.GetTop()
}

// PushResult pushes a single Lua value onto the stack and returns 1.
func (m *Manager) PushResult(val lua.LValue) int {
	m.L.Push(val)

	return 1
}

// PushResults pushes multiple Lua values onto the stack and returns the number of values pushed.
func (m *Manager) PushResults(vals ...lua.LValue) int {
	for _, val := range vals {
		m.L.Push(val)
	}

	return len(vals)
}

// PushError pushes nil and the error message onto the stack, returning 2.
// This is a common pattern in this project for returning errors to Lua.
func (m *Manager) PushError(err error) int {
	m.L.Push(lua.LNil)
	m.L.Push(lua.LString(err.Error()))

	return 2
}

// PushOK pushes the string "OK" onto the stack and returns 1.
func (m *Manager) PushOK() int {
	m.L.Push(lua.LString("OK"))

	return 1
}
