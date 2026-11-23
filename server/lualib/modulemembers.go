// Copyright (C) 2026 Christian Rößner
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
	"sort"

	lua "github.com/yuin/gopher-lua"
)

// moduleMembersRegistryKey names the registry slot that holds the module members cached for one Lua VM.
const moduleMembersRegistryKey = "_NAUTHILUS_MODULE_MEMBERS"

// moduleMemberCapacity is the initial room for the members of a captured module.
const moduleMemberCapacity = 16

// ModuleBuilder creates the complete table of a module the conventional way.
type ModuleBuilder func() *lua.LTable

// moduleMember is one immutable member of a module table.
type moduleMember struct {
	value lua.LValue
	name  string
}

// moduleMembers is the member list of one module together with the collaborators its functions capture.
//
// A module that holds a member a script could alter in place is not shareable; it has no member list and is built
// again for every request.
type moduleMembers struct {
	members   []moduleMember
	owners    []any
	shareable bool
}

// moduleMemberCache keeps the module members of one Lua VM by module key.
type moduleMemberCache struct {
	modules map[string]*moduleMembers
}

// NewRequestModule returns the table of the module identified by key for the current request.
//
// Creating the Go functions of a module is the expensive part of binding it, and it yields equivalent functions
// for every request as long as the collaborators they capture (configuration, logger, clients) stay the same.
// The members are therefore built once per Lua VM and owner set, and every request receives a table of its own
// that is filled from them: nothing a script stores in a module table outlives the request. The cached members
// never hold request data; it reaches the functions through the request bindings of the returned table.
//
// The owners are the collaborators that build captures. A different owner set rebuilds the members, so build must
// not capture anything that is not listed. spare reserves room for fields the caller adds to the returned table.
func NewRequestModule(L *lua.LState, key string, spare int, build ModuleBuilder, owners ...any) *lua.LTable {
	cache := moduleMemberCacheOf(L)
	if cache == nil {
		return build()
	}

	module := cache.modules[key]
	if module != nil && module.ownedBy(owners) {
		if module.shareable {
			return module.newTable(L, spare)
		}

		return build()
	}

	built := build()
	module = newModuleMembers(built, owners)
	cache.modules[key] = module

	if module.shareable {
		return module.newTable(L, spare)
	}

	return built
}

// moduleMemberCacheOf returns the member cache of the VM that L belongs to and creates it on first use.
func moduleMemberCacheOf(L *lua.LState) *moduleMemberCache {
	if L == nil {
		return nil
	}

	registry, ok := L.Get(lua.RegistryIndex).(*lua.LTable)
	if !ok {
		return nil
	}

	if holder, isUserData := registry.RawGetString(moduleMembersRegistryKey).(*lua.LUserData); isUserData {
		if cache, isCache := holder.Value.(*moduleMemberCache); isCache {
			return cache
		}
	}

	cache := &moduleMemberCache{modules: make(map[string]*moduleMembers)}
	holder := L.NewUserData()
	holder.Value = cache

	registry.RawSetString(moduleMembersRegistryKey, holder)

	return cache
}

// newModuleMembers captures the members of a freshly built module table.
func newModuleMembers(built *lua.LTable, owners []any) *moduleMembers {
	module := &moduleMembers{owners: append([]any(nil), owners...)}
	if built == nil || built.Metatable != lua.LNil {
		return module
	}

	members := make([]moduleMember, 0, moduleMemberCapacity)
	shareable := true

	built.ForEach(func(key lua.LValue, value lua.LValue) {
		name, isString := key.(lua.LString)
		if !isString || !isImmutableMember(value) {
			shareable = false

			return
		}

		members = append(members, moduleMember{name: string(name), value: value})
	})

	if !shareable {
		return module
	}

	sort.Slice(members, func(i, j int) bool {
		return members[i].name < members[j].name
	})

	module.members = members
	module.shareable = true

	return module
}

// isImmutableMember reports whether a script that holds the value cannot alter it for a later request.
//
// Tables and Lua functions are mutable through their fields and upvalues, and so are Go closures with upvalues.
// A plain Go function exposes no state to Lua, scalars are values, and a userdata is opaque to scripts.
func isImmutableMember(value lua.LValue) bool {
	switch typed := value.(type) {
	case *lua.LFunction:
		return typed.IsG && len(typed.Upvalues) == 0
	case *lua.LUserData:
		return typed.Metatable == lua.LNil || typed.Metatable == nil
	case lua.LString, lua.LNumber, lua.LInteger, lua.LBool:
		return true
	default:
		return false
	}
}

// ownedBy reports whether the members were built for exactly the given collaborators.
func (m *moduleMembers) ownedBy(owners []any) bool {
	if len(m.owners) != len(owners) {
		return false
	}

	for index, owner := range owners {
		if !sameOwner(m.owners[index], owner) {
			return false
		}
	}

	return true
}

// newTable creates the module table of one request with room for spare additional fields.
func (m *moduleMembers) newTable(L *lua.LState, spare int) *lua.LTable {
	table := L.CreateTable(0, len(m.members)+spare)

	for index := range m.members {
		table.RawSetString(m.members[index].name, m.members[index].value)
	}

	return table
}

// sameOwner reports whether two collaborators are the identical instance.
//
// Values whose dynamic type cannot be compared count as different, which only costs a rebuild.
func sameOwner(left any, right any) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	if !reflect.ValueOf(left).Comparable() || !reflect.ValueOf(right).Comparable() {
		return false
	}

	return left == right
}
