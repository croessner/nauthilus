package redislib

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisRunScript(t *testing.T) {
	testCases := []struct {
		name             string
		script           string
		keys             []string
		args             []any
		expectErr        bool
		expectRes        string
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:      "ValidScript",
			script:    "return redis.call('set',KEYS[1],'bar')",
			keys:      []string{"foo"},
			args:      []any{},
			expectErr: false,
			expectRes: "mock result",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectEval("return redis.call('set',KEYS[1],'bar')", []string{"foo"}).SetVal("mock result")
			},
		},
		{
			name:      "InvalidScript",
			script:    "return redis.call('set',KEYS[1])", // missing value for 'set'
			keys:      []string{"foo"},
			args:      []any{},
			expectErr: true,
			expectRes: "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectEval("return redis.call('set',KEYS[1])", []string{"foo"}).SetErr(errors.New("missing value for 'set'"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tc.prepareMockRedis(mock)
			rediscli.WriteHandle = db

			L := lua.NewState()

			defer L.Close()

			// Set up script
			L.Push(lua.LString(tc.script))

			// No script uploads
			L.Push(lua.LString(""))

			// Set up keys
			keys := L.CreateTable(len(tc.keys), 0)
			for _, k := range tc.keys {
				keys.Append(lua.LString(k))
			}

			L.Push(keys)

			// Set up args
			args := L.CreateTable(len(tc.args), 0)
			for _, a := range tc.args {
				args.Append(lua.LString(a.(string))) // Annahme, dass args vom Typ string sind
			}

			L.Push(args)

			// Call function and check error
			numReturned := RedisRunScript(L)
			errReturned := L.Get(-2).String() != "nil"

			assert.Equal(t, tc.expectErr, errReturned, "")
			assert.Equal(t, 2, numReturned, "")

			// Check result if no error
			if !tc.expectErr && numReturned > 0 {
				resReturned := L.Get(-1).String()

				assert.Equal(t, tc.expectRes, resReturned, "")
			}

			// Check if everything expected was done
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestRedisUploadScript(t *testing.T) {
	testCases := []struct {
		name               string
		script             string
		uploadScriptName   string
		expectErr          bool
		expectedSHA        string
		prepareRedisUpload func(mock redismock.ClientMock)
	}{
		{
			name:             "CorrectScript",
			script:           "return 1",
			uploadScriptName: "mockScript1",
			expectErr:        false,
			expectedSHA:      "mockSHA",
			prepareRedisUpload: func(mock redismock.ClientMock) {
				mock.ExpectScriptLoad("return 1").SetVal("mockSHA")
			},
		},
		{
			name:             "FaultyScript",
			script:           "faulty script",
			uploadScriptName: "mockScript2",
			expectErr:        true,
			expectedSHA:      "",
			prepareRedisUpload: func(mock redismock.ClientMock) {
				mock.ExpectScriptLoad("faulty script").SetErr(errors.New("syntax error"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tc.prepareRedisUpload(mock)
			rediscli.WriteHandle = db

			L := lua.NewState()

			defer L.Close()

			// Set up script
			L.Push(lua.LString(tc.script))
			L.Push(lua.LString(tc.uploadScriptName))

			numReturned := RedisUploadScript(L)
			errReturned := L.Get(-2).String() != "nil"

			assert.Equal(t, tc.expectErr, errReturned, "")
			assert.Equal(t, 2, numReturned, "")

			// Check result if no error
			if !tc.expectErr && numReturned > 0 {
				shaReturned := L.Get(-1).String()

				assert.Equal(t, tc.expectedSHA, shaReturned, "")
			}

			// Check if everything expected was done
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
