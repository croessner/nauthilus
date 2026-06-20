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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisSet_WithOptionsTable(t *testing.T) {
	now := time.Now().Add(2 * time.Hour).Truncate(time.Second)

	for _, tt := range redisSetOptionsCases(now) {
		t.Run(tt.name, func(t *testing.T) {
			runRedisSetOptionsCase(t, tt)
		})
	}
}

type redisSetOptionsCase struct {
	name           string
	luaOptions     string
	expect         func(mock redismock.ClientMock)
	expectedResult lua.LValue
	expectedErr    lua.LValue
}

// redisSetOptionsCases returns SET option-table behavior cases.
func redisSetOptionsCases(now time.Time) []redisSetOptionsCase {
	cases := redisSetExpirationOptionsCases(now)
	cases = append(cases, redisSetModeOptionsCases()...)
	cases = append(cases, redisSetErrorOptionsCases()...)

	return cases
}

// redisSetExpirationOptionsCases returns SET expiration option cases.
func redisSetExpirationOptionsCases(now time.Time) []redisSetOptionsCase {
	return []redisSetOptionsCase{
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
	}
}

// redisSetModeOptionsCases returns SET mode and result option cases.
func redisSetModeOptionsCases() []redisSetOptionsCase {
	return []redisSetOptionsCase{
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
	}
}

// redisSetErrorOptionsCases returns SET error propagation cases.
func redisSetErrorOptionsCases() []redisSetOptionsCase {
	return []redisSetOptionsCase{
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
}

// runRedisSetOptionsCase executes one SET option-table scenario.
func runRedisSetOptionsCase(t *testing.T, tt redisSetOptionsCase) {
	t.Helper()

	L, mock, _ := newRedisLuaCommandState(t)
	tt.expect(mock)
	runRedisSetOptionsScript(t, L, tt.luaOptions)

	assertLuaValueEqual(t, "redis_set", L.GetGlobal("result"), tt.expectedResult)
	checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)
	assertRedisExpectationsAndClear(t, mock)
}

// runRedisSetOptionsScript executes the SET option-table Lua call.
func runRedisSetOptionsScript(t *testing.T, L *lua.LState, luaOptions string) {
	t.Helper()

	L.SetGlobal("k", lua.LString("k"))
	L.SetGlobal("v", lua.LString("v"))

	script := fmt.Sprintf(`local r = require("nauthilus_redis"); result, err = r.redis_set("default", k, v, %s)`, luaOptions)
	if err := L.DoString(script); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}
}

func TestRedisSet_WithOptionsTable_NilSemantics(t *testing.T) {
	for _, tt := range redisSetNilSemanticsCases() {
		t.Run(tt.name, func(t *testing.T) {
			runRedisSetNilSemanticsCase(t, tt)
		})
	}
}

type redisSetNilSemanticsCase struct {
	name       string
	setArgs    redis.SetArgs
	luaOptions string
}

// redisSetNilSemanticsCases returns SET cases where Redis nil is a successful result.
func redisSetNilSemanticsCases() []redisSetNilSemanticsCase {
	return []redisSetNilSemanticsCase{
		{name: "NX unmet returns nil no error", setArgs: redis.SetArgs{Mode: "NX"}, luaOptions: `{ nx = true }`},
		{name: "XX unmet returns nil no error", setArgs: redis.SetArgs{Mode: "XX"}, luaOptions: `{ xx = true }`},
		{name: "GET no old value returns nil no error", setArgs: redis.SetArgs{Get: true}, luaOptions: `{ get = true }`},
	}
}

// runRedisSetNilSemanticsCase executes one SET nil-semantics scenario.
func runRedisSetNilSemanticsCase(t *testing.T, tt redisSetNilSemanticsCase) {
	t.Helper()

	L, mock, _ := newRedisLuaCommandState(t)
	mock.ExpectSetArgs("k", "v", tt.setArgs).RedisNil()
	runRedisSetOptionsScript(t, L, tt.luaOptions)

	if got := L.GetGlobal("result"); got != lua.LNil {
		t.Errorf("expected result nil, got %v", got)
	}

	if gotErr := L.GetGlobal("err"); gotErr != lua.LNil {
		t.Errorf("expected err nil, got %v", gotErr)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mock expectations were not met: %v", err)
	}

	mock.ClearExpect()
}
