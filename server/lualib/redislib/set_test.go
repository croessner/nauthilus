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
