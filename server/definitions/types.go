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

package definitions

// Backend is a numeric identifier for a database backend.
type Backend uint8

// AuthResult is the numeric result of a password check done by handlePassword()
type AuthResult uint8

// LDAPCommand represents the LDAP operation like search, add or modify.
type LDAPCommand uint8

type LDAPSubCommand uint8

// LDAPState is the tri-state flag for the LDAPPool
type LDAPState uint8

// Algorithm is a password algorithm type.
type Algorithm uint8

// PasswordOption is a password encoding type.
type PasswordOption uint8

func (b Backend) String() string {
	switch b {
	case BackendCache:
		return BackendCacheName
	case BackendLDAP:
		return BackendLDAPName
	case BackendLua:
		return BackendLuaName
	case BackendLocalCache:
		return BackendLocalCacheName
	default:
		return BackendUnknownName
	}
}

// DbgModule represents a debug module identifier.
type DbgModule uint8

// LuaAction represents a numeric identifier for a Lua action.
type LuaAction uint8

// LuaCommand is a numeric identifier for a Lua command.
type LuaCommand uint8

// CacheNameBackend is a numeric identifier for a cache name backend.
type CacheNameBackend uint8

// Monitoring is a numeric identifier for various monitoring flags in the Authentication struct.
type Monitoring uint8
