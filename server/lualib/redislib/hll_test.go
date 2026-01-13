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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisPFAdd(t *testing.T) {
	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})

	tests := []struct {
		name        string
		key         string
		values      []any
		expectedRes lua.LValue
		expectedErr lua.LValue
		setupMock   func(m redismock.ClientMock)
	}{
		{
			name:        "AddNewElements",
			key:         "hll:1",
			values:      []any{"a", "b"},
			expectedRes: lua.LNumber(1),
			expectedErr: lua.LNil,
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFAdd("hll:1", []any{"a", "b"}).SetVal(1)
			},
		},
		{
			name:        "NoChange",
			key:         "hll:1",
			values:      []any{"a"},
			expectedRes: lua.LNumber(0),
			expectedErr: lua.LNil,
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFAdd("hll:1", []any{"a"}).SetVal(0)
			},
		},
		{
			name:        "WithError",
			key:         "hll:1",
			values:      []any{"x"},
			expectedRes: lua.LNil,
			expectedErr: lua.LString("some error"),
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFAdd("hll:1", []any{"x"}).SetErr(errors.New("some error"))
			},
		},
	}

	L := lua.NewState()
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile()))
	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.setupMock(mock)
			rediscli.NewTestClient(db)

			L.SetGlobal("key", lua.LString(tt.key))

			valueStr := ""
			for _, v := range tt.values {
				valueStr += fmt.Sprintf(", %s", formatLuaValue(v))
			}

			if err := L.DoString(fmt.Sprintf(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_pfadd("default", key%s)`, valueStr)); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedRes.Type() || gotResult.String() != tt.expectedRes.String() {
				t.Errorf("redis_pfadd() result = %v, want %v", gotResult, tt.expectedRes)
			}

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisPFCount(t *testing.T) {
	tests := []struct {
		name        string
		keys        []string
		expectedRes lua.LValue
		expectedErr lua.LValue
		setupMock   func(m redismock.ClientMock)
	}{
		{
			name:        "SingleKey",
			keys:        []string{"hll:1"},
			expectedRes: lua.LNumber(2),
			expectedErr: lua.LNil,
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFCount("hll:1").SetVal(2)
			},
		},
		{
			name:        "MultipleKeys",
			keys:        []string{"hll:1", "hll:2"},
			expectedRes: lua.LNumber(5),
			expectedErr: lua.LNil,
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFCount("hll:1", "hll:2").SetVal(5)
			},
		},
		{
			name:        "WithError",
			keys:        []string{"hll:1"},
			expectedRes: lua.LNil,
			expectedErr: lua.LString("some error"),
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFCount("hll:1").SetErr(errors.New("some error"))
			},
		},
	}

	L := lua.NewState()
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile()))
	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.setupMock(mock)
			rediscli.NewTestClient(db)

			for i, k := range tt.keys {
				L.SetGlobal(fmt.Sprintf("k%d", i+1), lua.LString(k))
			}

			var keysLua string
			for i := range tt.keys {
				if i == 0 {
					keysLua = "k1"
				} else {
					keysLua += fmt.Sprintf(", k%d", i+1)
				}
			}

			if err := L.DoString(fmt.Sprintf(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_pfcount("default", %s)`, keysLua)); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedRes.Type() || gotResult.String() != tt.expectedRes.String() {
				t.Errorf("redis_pfcount() result = %v, want %v", gotResult, tt.expectedRes)
			}

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisPFMerge(t *testing.T) {
	tests := []struct {
		name        string
		dest        string
		sources     []string
		expectedRes lua.LValue
		expectedErr lua.LValue
		setupMock   func(m redismock.ClientMock)
	}{
		{
			name:        "MergeTwo",
			dest:        "hll:dst",
			sources:     []string{"hll:1", "hll:2"},
			expectedRes: lua.LString("OK"),
			expectedErr: lua.LNil,
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFMerge("hll:dst", []string{"hll:1", "hll:2"}...).SetVal("OK")
			},
		},
		{
			name:        "WithError",
			dest:        "hll:dst",
			sources:     []string{"hll:1"},
			expectedRes: lua.LNil,
			expectedErr: lua.LString("some error"),
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFMerge("hll:dst", []string{"hll:1"}...).SetErr(errors.New("some error"))
			},
		},
	}

	L := lua.NewState()
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile()))
	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.setupMock(mock)
			rediscli.NewTestClient(db)

			L.SetGlobal("dest", lua.LString(tt.dest))
			for i, s := range tt.sources {
				L.SetGlobal(fmt.Sprintf("s%d", i+1), lua.LString(s))
			}

			var sourcesLua string
			for i := range tt.sources {
				if i == 0 {
					sourcesLua = "s1"
				} else {
					sourcesLua += fmt.Sprintf(", s%d", i+1)
				}
			}

			if err := L.DoString(fmt.Sprintf(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_pfmerge("default", dest, %s)`, sourcesLua)); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedRes.Type() || gotResult.String() != tt.expectedRes.String() {
				t.Errorf("redis_pfmerge() result = %v, want %v", gotResult, tt.expectedRes)
			}

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}
