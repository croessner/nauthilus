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

package redislib

import (
	"errors"

	"github.com/croessner/nauthilus/server/lualib/luastack"
	lua "github.com/yuin/gopher-lua"
)

// RedisEncrypt encrypts a string using the Redis security manager.
func (rm *RedisManager) RedisEncrypt(L *lua.LState) int {
	stack := luastack.NewManager(L)
	_ = stack.CheckAny(1)
	plaintext := stack.CheckString(2)

	sm := rm.client.GetSecurityManager()
	if sm == nil {
		return stack.PushError(errors.New("security manager not available"))
	}

	ciphertext, err := sm.Encrypt(plaintext)
	if err != nil {
		return stack.PushError(err)
	}

	return stack.PushResults(lua.LString(ciphertext), lua.LNil)
}

// RedisDecrypt decrypts a string using the Redis security manager.
func (rm *RedisManager) RedisDecrypt(L *lua.LState) int {
	stack := luastack.NewManager(L)
	_ = stack.CheckAny(1)
	ciphertext := stack.CheckString(2)

	sm := rm.client.GetSecurityManager()
	if sm == nil {
		return stack.PushError(errors.New("security manager not available"))
	}

	plaintext, err := sm.Decrypt(ciphertext)
	if err != nil {
		return stack.PushError(err)
	}

	return stack.PushResults(lua.LString(plaintext), lua.LNil)
}

// RedisIsEncryptionEnabled checks if encryption is enabled in the Redis security manager.
func (rm *RedisManager) RedisIsEncryptionEnabled(L *lua.LState) int {
	stack := luastack.NewManager(L)
	_ = stack.CheckAny(1)

	sm := rm.client.GetSecurityManager()
	if sm == nil {
		return stack.PushResults(lua.LFalse)
	}

	return stack.PushResults(lua.LBool(sm.IsEncryptionEnabled()))
}
