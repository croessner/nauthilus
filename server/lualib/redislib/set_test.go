package redislib

import (
	"errors"
	"fmt"
	"testing"

	"github.com/croessner/nauthilus/server/global"
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

	L := lua.NewState()

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.setupMock(mock)
			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))

			valueStr := ""
			for _, v := range tt.values {
				valueStr += fmt.Sprintf(", %s", formatLuaValue(v))
			}

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisSAddFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisSAdd)
			if redisSAddFunction == nil {
				t.Fatalf("Function nauthilus.redis_sadd does not exist")
			}

			err := L.DoString(fmt.Sprintf("result, err = nauthilus.redis_sadd(key%s)", valueStr))
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

	L := lua.NewState()

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.setupMock(mock)
			rediscli.ReadHandle = db

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("value", ConvertGoToLuaValue(tt.value))

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisSIsMemberFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisSIsMember)
			if redisSIsMemberFunction == nil {
				t.Fatalf("Function nauthilus.redis_sismember does not exist")
			}

			err := L.DoString(fmt.Sprintf("result, err = nauthilus.redis_sismember(key, value)"))
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
	L := lua.NewState()

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.setupMock(mock)
			rediscli.ReadHandle = db

			L.SetGlobal("key", lua.LString(tt.key))

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisSMembersFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisSMembers)
			if redisSMembersFunction == nil {
				t.Fatalf("Function nautilus.redis_smembers does not exist")
			}

			err := L.DoString(`result, err = nauthilus.redis_smembers(key)`)
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

	L := lua.NewState()

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.setupMock(mock)
			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))

			valueStr := ""
			for _, v := range tt.values {
				valueStr += fmt.Sprintf(", %s", formatLuaValue(v))
			}

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisSRemFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisSRem)
			if redisSRemFunction == nil {
				t.Fatalf("Function nauthilus.redis_srem does not exist")
			}

			err := L.DoString(fmt.Sprintf("result, err = nauthilus.redis_srem(key%s)", valueStr))
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
