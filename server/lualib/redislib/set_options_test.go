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

package redislib

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisSet_WithOptionsTable(t *testing.T) {
	testFile := &config.FileSettings{Server: &config.ServerSection{}}
	config.SetTestFile(testFile)
	util.SetDefaultConfigFile(testFile)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	now := time.Now().Add(2 * time.Hour).Truncate(time.Second)

	tests := []struct {
		name           string
		luaOptions     string
		expect         func(mock redismock.ClientMock)
		expectedResult lua.LValue
		expectedErr    lua.LValue
	}{
		{
			name:       "EX seconds",
			luaOptions: `{ ex = 10 }`,
			expect: func(mock redismock.ClientMock) {
				mock.ExpectSetArgs("k", "v", redis.SetArgs{TTL: 10 * time.Second}).SetVal("OK")
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
		},
		{
			name:       "PX milliseconds",
			luaOptions: `{ px = 1500 }`,
			expect: func(mock redismock.ClientMock) {
				mock.ExpectSetArgs("k", "v", redis.SetArgs{TTL: 1500 * time.Millisecond}).SetVal("OK")
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
		},
		{
			name:       "EXAT unix seconds",
			luaOptions: fmt.Sprintf(`{ exat = %d }`, now.Unix()),
			expect: func(mock redismock.ClientMock) {
				mock.ExpectSetArgs("k", "v", redis.SetArgs{ExpireAt: time.Unix(now.Unix(), 0)}).SetVal("OK")
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
		},
		{
			name:       "PXAT unix ms",
			luaOptions: fmt.Sprintf(`{ pxat = %d }`, now.UnixMilli()),
			expect: func(mock redismock.ClientMock) {
				mock.ExpectSetArgs("k", "v", redis.SetArgs{ExpireAt: time.Unix(0, now.UnixMilli()*int64(time.Millisecond))}).SetVal("OK")
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
		},
		{
			name:       "NX option",
			luaOptions: `{ nx = true }`,
			expect: func(mock redismock.ClientMock) {
				mock.ExpectSetArgs("k", "v", redis.SetArgs{Mode: "NX"}).SetVal("OK")
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
		},
		{
			name:       "XX option",
			luaOptions: `{ xx = true }`,
			expect: func(mock redismock.ClientMock) {
				mock.ExpectSetArgs("k", "v", redis.SetArgs{Mode: "XX"}).SetVal("OK")
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
		},
		{
			name:       "GET option returns old value",
			luaOptions: `{ get = true }`,
			expect: func(mock redismock.ClientMock) {
				mock.ExpectSetArgs("k", "v", redis.SetArgs{Get: true}).SetVal("old")
			},
			expectedResult: lua.LString("old"),
			expectedErr:    lua.LNil,
		},
		{
			name:       "KEEPTTL option",
			luaOptions: `{ keepttl = true }`,
			expect: func(mock redismock.ClientMock) {
				mock.ExpectSetArgs("k", "v", redis.SetArgs{KeepTTL: true}).SetVal("OK")
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
		},
		{
			name:       "Combination NX + EX",
			luaOptions: `{ nx = true, ex = 5 }`,
			expect: func(mock redismock.ClientMock) {
				mock.ExpectSetArgs("k", "v", redis.SetArgs{Mode: "NX", TTL: 5 * time.Second}).SetVal("OK")
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
		},
		{
			name:       "Error bubbles up",
			luaOptions: `{ ex = 1 }`,
			expect: func(mock redismock.ClientMock) {
				mock.ExpectSetArgs("k", "v", redis.SetArgs{TTL: 1 * time.Second}).SetErr(errors.New("boom"))
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("boom"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock conn.")
			}

			tt.expect(mock)
			client := rediscli.NewTestClient(db)
			SetDefaultClient(client)

			L := lua.NewState()
			defer L.Close()
			L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), testFile, client))

			L.SetGlobal("k", lua.LString("k"))
			L.SetGlobal("v", lua.LString("v"))

			script := fmt.Sprintf(`local r = require("nauthilus_redis"); result, err = r.redis_set("default", k, v, %s)`, tt.luaOptions)
			if err := L.DoString(script); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			got := L.GetGlobal("result")
			if got.Type() != tt.expectedResult.Type() || got.String() != tt.expectedResult.String() {
				t.Errorf("redis_set() result = %v, want %v", got.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisSet_WithOptionsTable_NilSemantics(t *testing.T) {
	testFile := &config.FileSettings{Server: &config.ServerSection{}}
	config.SetTestFile(testFile)
	util.SetDefaultConfigFile(testFile)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	tests := []struct {
		name       string
		setArgs    redis.SetArgs
		luaOptions string
	}{
		{name: "NX unmet returns nil no error", setArgs: redis.SetArgs{Mode: "NX"}, luaOptions: `{ nx = true }`},
		{name: "XX unmet returns nil no error", setArgs: redis.SetArgs{Mode: "XX"}, luaOptions: `{ xx = true }`},
		{name: "GET no old value returns nil no error", setArgs: redis.SetArgs{Get: true}, luaOptions: `{ get = true }`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock conn.")
			}

			mock.ExpectSetArgs("k", "v", tt.setArgs).RedisNil()
			client := rediscli.NewTestClient(db)
			SetDefaultClient(client)

			L := lua.NewState()
			defer L.Close()
			L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), testFile, client))

			L.SetGlobal("k", lua.LString("k"))
			L.SetGlobal("v", lua.LString("v"))

			script := fmt.Sprintf(`local r = require("nauthilus_redis"); result, err = r.redis_set("default", k, v, %s)`, tt.luaOptions)
			if err := L.DoString(script); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			// result should be nil, err should be nil
			got := L.GetGlobal("result")
			if got != lua.LNil {
				t.Errorf("expected result nil, got %v", got)
			}
			gotErr := L.GetGlobal("err")
			if gotErr != lua.LNil {
				t.Errorf("expected err nil, got %v", gotErr)
			}

			mock.ClearExpect()
		})
	}
}
