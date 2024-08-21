package lualib

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

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

func formatLuaValue(val any) string {
	switch v := val.(type) {
	case string:
		return fmt.Sprintf(`"%s"`, v)
	case int, int64, float64, bool:
		return fmt.Sprintf("%v", v)
	case lua.LValue:
		return v.String()
	default:
		return "nil"
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
			expectedErr: lua.LString("redis: nil"),
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

func TestRedisSet(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		value            lua.LValue
		expiration       int
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "SetKeyValue",
			key:            "testKey",
			value:          lua.LString("testValue"),
			expiration:     30,
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSet("testKey", "testValue", time.Duration(30)*time.Second).SetVal("OK")
			},
		},
		{
			name:           "SetKeyValueWithoutExpiration",
			key:            "anotherKey",
			value:          lua.LString("anotherValue"),
			expiration:     0,
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSet("anotherKey", "anotherValue", 0).SetVal("OK")
			},
		},
		{
			name:           "SetKeyValueWithError",
			key:            "testKey",
			value:          lua.LString("testValue"),
			expiration:     30,
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSet("testKey", "testValue", time.Duration(30)*time.Second).SetErr(errors.New("some error"))
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
			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("value", tt.value)
			L.SetGlobal("expiration", lua.LNumber(tt.expiration))

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisSetFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisSet)
			if redisSetFunction == nil {
				t.Fatalf("Function nauthilus.redis_set does not exist")
			}

			err := L.DoString(`result, err = nauthilus.redis_set(key, value, expiration)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_set() gotResult = %v, want %v", gotResult.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisExpire(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expiration       lua.LNumber
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "ExpireWithExistingKey",
			key:            "testKey",
			expiration:     60,
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectExpire("testKey", time.Duration(60)*time.Second).SetVal(true)
			},
		},
		{
			name:           "ExpireWithNonExistingKey",
			key:            "missingKey",
			expiration:     30,
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectExpire("missingKey", time.Duration(30)*time.Second).SetVal(false)
			},
		},
		{
			name:           "ExpireWithError",
			key:            "keyWithError",
			expiration:     10,
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectExpire("keyWithError", time.Duration(10)*time.Second).SetErr(errors.New("some error"))
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
			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("expiration", tt.expiration)

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisExpireFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisExpire)
			if redisExpireFunction == nil {
				t.Fatalf("Function nauthilus.redis_expire does not exist")
			}

			err := L.DoString(`result, err = nauthilus.redis_expire(key, expiration)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_expire() gotResult = %v, want %v", gotResult.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisIncr(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "IncrementNonExistingKey",
			key:            "testKey",
			expectedResult: lua.LNumber(1),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectIncr("testKey").SetVal(1)
			},
		},
		{
			name:           "IncrementExistingKey",
			key:            "existingKey",
			expectedResult: lua.LNumber(2),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectIncr("existingKey").SetVal(2)
			},
		},
		{
			name:           "IncrementKeyWithError",
			key:            "keyWithError",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectIncr("keyWithError").SetErr(errors.New("some error"))
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
			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisIncrFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisIncr)
			if redisIncrFunction == nil {
				t.Fatalf("Function nauthilus.redis_incr does not exist")
			}

			err := L.DoString(`result, err = nauthilus.redis_incr(key)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || lua.LVAsNumber(gotResult) != lua.LVAsNumber(tt.expectedResult) {
				t.Errorf("nauthilus.redis_incr() gotResult = %v, want %v", gotResult, tt.expectedResult)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisDel(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "DeleteExistingKey",
			key:            "existingKey",
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectDel("existingKey").SetVal(1)
			},
		},
		{
			name:           "DeleteNonExistingKey",
			key:            "nonExistingKey",
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectDel("nonExistingKey").SetVal(0)
			},
		},
		{
			name:           "DeleteWithError",
			key:            "keyWithError",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectDel("keyWithError").SetErr(errors.New("some error"))
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
			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisDelFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisDel)
			if redisDelFunction == nil {
				t.Fatalf("Function nauthilus.redis_del does not exist")
			}

			err := L.DoString(`result, err = nauthilus.redis_del(key)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_del() gotResult = %v, want %v", gotResult.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisHGet(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		field            string
		valueType        string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "GetExistingField",
			key:            "existingKey",
			field:          "existingField",
			valueType:      global.TypeString,
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGet("existingKey", "existingField").SetVal("OK")
			},
		},
		{
			name:           "GetNonExistingField",
			key:            "existingKey",
			field:          "nonExistingField",
			valueType:      global.TypeString,
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGet("existingKey", "nonExistingField").RedisNil()
			},
		},
		{
			name:           "GetFieldWithError",
			key:            "keyWithError",
			field:          "fieldWithError",
			valueType:      global.TypeString,
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGet("keyWithError", "fieldWithError").SetErr(errors.New("some error"))
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
			L.SetGlobal("field", lua.LString(tt.field))
			L.SetGlobal("valueType", lua.LString(tt.valueType))

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisHGetFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisHGet)
			if redisHGetFunction == nil {
				t.Fatalf("Function nauthilus.redis_hget does not exist")
			}

			err := L.DoString(`result, err = nauthilus.redis_hget(key, field, valueType)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_hget() gotResult = %v, want %v", gotResult.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisHSet(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		kvPairs          []any
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "SetStringKeyValuePairs",
			key:            "testKey",
			kvPairs:        []any{"field1", "value1", "field2", "value2"},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHSet("testKey", "field1", "value1", "field2", "value2").SetVal(2)
			},
		},
		{
			name:           "SetNilKeyValuePairs",
			key:            "nilKey",
			kvPairs:        []any{},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("Invalid number of arguments"),
		},
		{
			name:           "SetKeyValuePairsWithError",
			key:            "errorKey",
			kvPairs:        []any{"field1", "value1"},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHSet("errorKey", "field1", "value1").SetErr(errors.New("some error"))
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

			if tt.prepareMockRedis != nil {
				tt.prepareMockRedis(mock)
			}

			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))

			globals := L.NewTable()
			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisHSetFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisHSet)
			if redisHSetFunction == nil {
				t.Fatalf("Function nauthilus.redis_hset does not exist")
			}

			kvPairsStr := ""

			for i := 0; i < len(tt.kvPairs); i += 2 {
				field := formatLuaValue(tt.kvPairs[i])
				value := formatLuaValue(tt.kvPairs[i+1])

				kvPairsStr += fmt.Sprintf(", %s, %s", field, value)
			}

			luaScript := fmt.Sprintf(`result, err = nauthilus.redis_hset(key%s)`, kvPairsStr)

			err := L.DoString(luaScript)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_hset() gotResult = %v, want %v", gotResult.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisHDel(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		fields           []string
		expectedRes      string
		expectedErr      string
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:        "DeleteExistingField",
			key:         "testKey",
			fields:      []string{"field1"},
			expectedRes: "OK",
			expectedErr: "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHDel("testKey", "field1").SetVal(1)
			},
		},
		{
			name:        "DeleteNonExistingField",
			key:         "testKey",
			fields:      []string{"field1"},
			expectedRes: "OK",
			expectedErr: "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHDel("testKey", "field1").SetVal(0)
			},
		},
		{
			name:        "DeleteFromNonExistingKey",
			key:         "nonExistingKey",
			fields:      []string{"field1"},
			expectedRes: "OK",
			expectedErr: "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHDel("nonExistingKey", "field1").SetVal(0)
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
			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))
			for index, field := range tt.fields {
				L.SetGlobal(fmt.Sprintf("field%d", index+1), lua.LString(field))
			}

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisHDelFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisHDel)
			if redisHDelFunction == nil {
				t.Fatalf("Function nauthilus.redis_hdel does not exist")
			}

			err := L.DoString(fmt.Sprintf(`result, err = nauthilus.redis_hdel(key, %s)`, strings.Join(tt.fields, ", ")))
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotRes := L.GetGlobal("result").String()
			if gotRes != tt.expectedRes {
				t.Errorf("nauthilus.redis_hdel() gotRes = %v, want %v", gotRes, tt.expectedRes)
			}

			gotErr := L.GetGlobal("err")
			if gotErr != lua.LNil && gotErr.String() != tt.expectedErr {
				t.Errorf("nauthilus.redis_hdel() gotErr = %v, want %v", gotErr.String(), tt.expectedErr)
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisHLen(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expectedLength   int64
		expectedErr      string
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "ExistingKey",
			key:            "testKey",
			expectedLength: 2,
			expectedErr:    "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHLen("testKey").SetVal(2)
			},
		},
		{
			name:           "NonExistingKey",
			key:            "missingKey",
			expectedLength: 0,
			expectedErr:    "redis: nil",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHLen("missingKey").RedisNil()
			},
		},
		{
			name:           "RedisError",
			key:            "errorKey",
			expectedLength: 0,
			expectedErr:    "connection error",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHLen("errorKey").SetErr(errors.New("connection error"))
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

			globals := L.NewTable()

			SetUPRedisFunctions(globals, L)
			L.SetGlobal(global.LuaDefaultTable, globals)

			redisHLenFunction := L.GetGlobal(global.LuaDefaultTable).(*lua.LTable).RawGetString(global.LuaFnRedisHLen)
			if redisHLenFunction == nil {
				t.Fatalf("Function nauthilus.redis_hlen does not exist")
			}

			err := L.DoString(`result, err = nauthilus.redis_hlen(key)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotLength := L.GetGlobal("result")
			if gotLength != lua.LNil && int64(gotLength.(lua.LNumber)) != tt.expectedLength {
				t.Errorf("nauthilus.redis_hlen() gotLength = %v, want %v", int64(gotLength.(lua.LNumber)), tt.expectedLength)
			}

			gotErr := L.GetGlobal("err")
			if tt.expectedErr != "" && gotErr.String() != tt.expectedErr {
				t.Errorf("Expected error: %v, but got: %v", tt.expectedErr, gotErr.String())
			}

			mock.ClearExpect()
		})
	}
}
