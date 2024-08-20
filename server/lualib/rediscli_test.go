package lualib

import (
	"testing"

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func checkLuaError(t *testing.T, gotErr lua.LValue, expectedErr lua.LValue) {
	if expectedErr != lua.LNil {
		if gotErr == lua.LNil || gotErr == nil {
			t.Errorf("expected error but 'err' is nil")
		} else if gotErr.Type() != expectedErr.Type() || gotErr.String() != expectedErr.String() {
			t.Errorf("gotErr = %v, want %v", gotErr.String(), expectedErr.String())
		}
	} else if gotErr != lua.LNil && gotErr != nil {
		t.Errorf("expected no error but got 'err' = %v", gotErr.String())
	}
}

func TestRedisGet(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		valueType        string
		expectedVal      lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:        "GetStringValue",
			key:         "testKey",
			valueType:   global.TypeString,
			expectedVal: lua.LString("testValue"),
			expectedErr: lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectGet("testKey").SetVal("testValue")
			},
		},
		{
			name:        "GetValueWithMissingKey",
			key:         "missingKey",
			valueType:   global.TypeString,
			expectedVal: lua.LNil,
			expectedErr: lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectGet("missingKey").RedisNil()
			},
		},
	}

	L := lua.NewState()

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.prepareMockRedis(mock)
			rediscli.ReadHandle = db

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("valueType", lua.LString(tt.valueType))

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisGetFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisGet)
			if redisGetFunction == nil {
				t.Fatalf("Function nauthilus.redis_get does not exist")
			}

			err := L.DoString(`result, err = nauthilus.redis_get(key, valueType)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotVal := L.GetGlobal("result")
			if gotVal.Type() != tt.expectedVal.Type() || gotVal.String() != tt.expectedVal.String() {
				t.Errorf("nauthilus.redis_get() gotVal = %v, want %v", gotVal.String(), tt.expectedVal.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}
