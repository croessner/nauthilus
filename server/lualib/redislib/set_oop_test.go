//go:build redislib_oop

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

package redislib

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisSAdd(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		values        []any
		expectedCount lua.LValue
		expectedErr   lua.LValue
		setupMock     func(mock redismock.ClientMock)
	}{
		{
			name:          "AddNewValues",
			key:           "existingKey",
			values:        []any{"val1", "val2"},
			expectedCount: lua.LNumber(2),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSAdd("existingKey", []any{"val1", "val2"}).SetVal(2)
			},
		},
		{
			name:          "AddExistingValues",
			key:           "existingKey",
			values:        []any{"val1", "val2"},
			expectedCount: lua.LNumber(0),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSAdd("existingKey", []any{"val1", "val2"}).SetVal(0)
			},
		},
		{
			name:          "AddWithErr",
			key:           "existingKey",
			values:        []any{"val1", "val2"},
			expectedCount: lua.LNil,
			expectedErr:   lua.LString("some error"),
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSAdd("existingKey", []any{"val1", "val2"}).SetErr(errors.New("some error"))
			},
		},
		{
			name:          "AddEmptyValues",
			key:           "existingKey",
			values:        []any{},
			expectedCount: lua.LNumber(0),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSAdd("existingKey", []any{}).SetVal(0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}
			client := rediscli.NewTestClient(db)
			SetDefaultClient(client)
			L := lua.NewState()
			defer L.Close()
			L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), client))

			tt.setupMock(mock)
			rediscli.NewTestClient(db)

			L.SetGlobal("key", lua.LString(tt.key))

			valueStr := ""
			for _, v := range tt.values {
				valueStr += fmt.Sprintf(", %s", formatLuaValue(v))
			}

			err := L.DoString(fmt.Sprintf(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_sadd("default", key%s)`, valueStr))
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedCount.Type() && gotResult.String() != tt.expectedCount.String() {
				t.Errorf("nauthilus.redis_sadd() gotResult = %d, want %d", gotResult, tt.expectedCount)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisSIsMember(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		value         any
		expectedValue lua.LValue
		expectedErr   lua.LValue
		setupMock     func(mock redismock.ClientMock)
	}{
		{
			name:          "ExistInSet",
			key:           "existingKey",
			value:         "existingValue",
			expectedValue: lua.LTrue,
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSIsMember("existingKey", "existingValue").SetVal(true)
			},
		},
		{
			name:          "NotExistInSet",
			key:           "existingKey",
			value:         "nonExistingValue",
			expectedValue: lua.LFalse,
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSIsMember("existingKey", "nonExistingValue").SetVal(false)
			},
		},
		{
			name:          "ErrOnMemberCheck",
			key:           "existingKey",
			value:         "anyValue",
			expectedValue: lua.LNil,
			expectedErr:   lua.LString("some error"),
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSIsMember("existingKey", "anyValue").SetErr(errors.New("some error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}
			client := rediscli.NewTestClient(db)
			SetDefaultClient(client)
			L := lua.NewState()
			defer L.Close()
			L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), client))

			tt.setupMock(mock)
			rediscli.NewTestClient(db)

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("value", convert.GoToLuaValue(L, tt.value))

			err := L.DoString(fmt.Sprintf(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_sismember("default", key, value)`))
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedValue.Type() && gotResult.String() != tt.expectedValue.String() {
				t.Errorf("nauthilus.redis_sismember() gotResult = %v, want %v", gotResult, tt.expectedValue)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisSMembers(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		expectedValue lua.LValue
		expectedErr   lua.LValue
		setupMock     func(mock redismock.ClientMock)
	}{
		{
			name:          "ValidKey",
			key:           "existingKey",
			expectedValue: createLuaTable([]string{"val1", "val2"}),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSMembers("existingKey").SetVal([]string{"val1", "val2"})
			},
		},
		{
			name:          "NonExistingKey",
			key:           "nonExistingKey",
			expectedValue: createLuaTable([]string{}),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSMembers("nonExistingKey").SetVal([]string{})
			},
		},
		{
			name:          "ErrOnSMembers",
			key:           "anyKey",
			expectedValue: lua.LNil,
			expectedErr:   lua.LString("some error"),
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSMembers("anyKey").SetErr(errors.New("some error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}
			client := rediscli.NewTestClient(db)
			SetDefaultClient(client)
			L := lua.NewState()
			defer L.Close()
			L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), client))

			tt.setupMock(mock)
			rediscli.NewTestClient(db)

			L.SetGlobal("key", lua.LString(tt.key))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_smembers("default", key)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if !(gotResult.Type() == tt.expectedValue.Type() && gotResult.String() == "nil") {
				if !luaTablesAreEqual(gotResult.(*lua.LTable), tt.expectedValue.(*lua.LTable)) {
					t.Errorf("nautilus.redis_smembers() gotResult = %v, want %v", gotResult, tt.expectedValue)
				}
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisSRem(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		values        []any
		expectedValue lua.LValue
		expectedErr   lua.LValue
		setupMock     func(mock redismock.ClientMock)
	}{
		{
			name:          "RemoveExistingValues",
			key:           "existingKey",
			values:        []any{"val1", "val2"},
			expectedValue: lua.LNumber(2),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSRem("existingKey", []any{"val1", "val2"}).SetVal(2)
			},
		},
		{
			name:          "RemoveNonExistingValues",
			key:           "existingKey",
			values:        []any{"nonExistingVal1", "nonExistingVal2"},
			expectedValue: lua.LNumber(0),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSRem("existingKey", []any{"nonExistingVal1", "nonExistingVal2"}).SetVal(0)
			},
		},
		{
			name:          "ErrorOnRemove",
			key:           "existingKey",
			values:        []any{"val1", "val2"},
			expectedValue: lua.LNil,
			expectedErr:   lua.LString("some error"),
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSRem("existingKey", []any{"val1", "val2"}).SetErr(errors.New("some error"))
			},
		},
		{
			name:          "RemoveNoValues",
			key:           "existingKey",
			values:        []any{},
			expectedValue: lua.LNumber(0),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSRem("existingKey", []any{}).SetVal(0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}
			client := rediscli.NewTestClient(db)
			SetDefaultClient(client)
			L := lua.NewState()
			defer L.Close()
			L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), client))

			tt.setupMock(mock)
			rediscli.NewTestClient(db)

			L.SetGlobal("key", lua.LString(tt.key))

			valueStr := ""
			for _, v := range tt.values {
				valueStr += fmt.Sprintf(", %s", formatLuaValue(v))
			}

			err := L.DoString(fmt.Sprintf(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_srem("default", key%s)`, valueStr))
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedValue.Type() && gotResult.String() != tt.expectedValue.String() {
				t.Errorf("nauthilus.redis_srem() gotResult = %v, want %v", gotResult, tt.expectedValue)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisSCard(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		expectedValue lua.LValue
		expectedErr   lua.LValue
		setupMock     func(mock redismock.ClientMock)
	}{
		{
			name:          "ValidKey",
			key:           "existingKey",
			expectedValue: lua.LNumber(2),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSCard("existingKey").SetVal(2)
			},
		},
		{
			name:          "NonExistingKey",
			key:           "nonExistingKey",
			expectedValue: lua.LNumber(0),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSCard("nonExistingKey").SetVal(0)
			},
		},
		{
			name:          "ErrorOnSCard",
			key:           "anyKey",
			expectedValue: lua.LNil,
			expectedErr:   lua.LString("some error"),
			setupMock: func(mock redismock.ClientMock) {
				mock.ExpectSCard("anyKey").SetErr(errors.New("some error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}
			client := rediscli.NewTestClient(db)
			SetDefaultClient(client)
			L := lua.NewState()
			defer L.Close()
			L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), client))

			tt.setupMock(mock)
			rediscli.NewTestClient(db)

			L.SetGlobal("key", lua.LString(tt.key))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_scard("default", key)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedValue.Type() || gotResult.String() != tt.expectedValue.String() {
				t.Errorf("nauthilus.redis_scard() gotResult = %v, want %v", gotResult, tt.expectedValue)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}
