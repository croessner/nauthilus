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
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
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
				t.Fatalf("Failed to create Redis mock conn.")
			}

			tc.prepareMockRedis(mock)
			client := rediscli.NewTestClient(db)
			SetDefaultClient(client)

			testFile := &config.FileSettings{Server: &config.ServerSection{}}
			config.SetTestFile(testFile)
			util.SetDefaultConfigFile(testFile)
			util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

			L := lua.NewState()
			defer L.Close()
			L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), testFile, client))

			L.SetGlobal("script", lua.LString(tc.script))
			L.SetGlobal("upload_name", lua.LString(""))

			keysTbl := L.NewTable()
			for _, k := range tc.keys {
				keysTbl.Append(lua.LString(k))
			}
			L.SetGlobal("keys", keysTbl)

			argsTbl := L.NewTable()
			for _, a := range tc.args {
				argsTbl.Append(lua.LString(a.(string)))
			}
			L.SetGlobal("args", argsTbl)

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_run_script("default", script, upload_name, keys, args)`)
			assert.NoError(t, err)

			resReturned := L.GetGlobal("result")
			errReturned := L.GetGlobal("err")

			if tc.expectErr {
				assert.NotEqual(t, lua.LNil, errReturned)
			} else {
				assert.Equal(t, lua.LNil, errReturned)
				assert.Equal(t, tc.expectRes, resReturned.String())
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
				t.Fatalf("Failed to create Redis mock conn.")
			}

			tc.prepareRedisUpload(mock)
			client := rediscli.NewTestClient(db)
			SetDefaultClient(client)

			testFile := &config.FileSettings{Server: &config.ServerSection{}}
			config.SetTestFile(testFile)
			util.SetDefaultConfigFile(testFile)
			util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

			L := lua.NewState()
			defer L.Close()
			L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), testFile, client))

			L.SetGlobal("script", lua.LString(tc.script))
			L.SetGlobal("upload_name", lua.LString(tc.uploadScriptName))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_upload_script("default", script, upload_name)`)
			assert.NoError(t, err)

			resReturned := L.GetGlobal("result")
			errReturned := L.GetGlobal("err")

			if tc.expectErr {
				assert.NotEqual(t, lua.LNil, errReturned)
			} else {
				assert.Equal(t, lua.LNil, errReturned)
				assert.Equal(t, tc.expectedSHA, resReturned.String())
			}

			// Check if everything expected was done
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
