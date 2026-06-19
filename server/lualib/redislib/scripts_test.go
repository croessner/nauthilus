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
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
	lua "github.com/yuin/gopher-lua"
)

const (
	customScriptName     = "customScript"
	customScriptSource   = "return 1"
	missingScriptName    = "missingScript"
	mockRedisResult      = "mock result"
	newScriptSHA         = "sha-new"
	noScriptRedisMessage = "NOSCRIPT No matching script. Please use EVAL."
	noScriptRedisPrefix  = "NOSCRIPT"
	oldScriptSHA         = "sha-old"
	redisScriptArg       = "bar"
	redisScriptKey       = "foo"
)

// redisScriptMockError provides realistic Redis error text without errors.New lint noise.
type redisScriptMockError string

// Error returns the Redis mock error text.
func (err redisScriptMockError) Error() string {
	return string(err)
}

// redisRunNamedUploadedScriptCase describes one named custom script run scenario.
type redisRunNamedUploadedScriptCase struct {
	name              string
	scriptName        string
	uploadedScript    UploadedScript
	expectedResult    string
	expectedErr       string
	expectedStoredSHA string
	prepareMockRedis  func(mock redismock.ClientMock)
}

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
			keys:      []string{redisScriptKey},
			args:      []any{},
			expectErr: false,
			expectRes: mockRedisResult,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectEval("return redis.call('set',KEYS[1],'bar')", []string{redisScriptKey}).SetVal(mockRedisResult)
			},
		},
		{
			name:      "InvalidScript",
			script:    "return redis.call('set',KEYS[1])", // missing value for 'set'
			keys:      []string{redisScriptKey},
			args:      []any{},
			expectErr: true,
			expectRes: "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectEval("return redis.call('set',KEYS[1])", []string{redisScriptKey}).SetErr(errors.New("missing value for 'set'"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resetScriptsRepository(t)

			L, mock := newRedisLuaTestState(t)
			tc.prepareMockRedis(mock)

			L.SetGlobal("script", lua.LString(tc.script))
			L.SetGlobal("upload_name", lua.LString(""))

			setLuaStringTable(L, "keys", tc.keys)
			setLuaAnyTable(L, "args", tc.args)

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

func TestRedisRunNamedUploadedScript(t *testing.T) {
	for _, tc := range namedUploadedScriptCases() {
		t.Run(tc.name, func(t *testing.T) {
			resetScriptsRepository(t)

			if hasStoredScript(tc.uploadedScript) {
				scriptsRepository.Set(tc.scriptName, tc.uploadedScript.SHA1, tc.uploadedScript.Source)
			}

			L, mock := newRedisLuaTestState(t)
			if tc.prepareMockRedis != nil {
				tc.prepareMockRedis(mock)
			}

			setLuaStringTable(L, "keys", []string{redisScriptKey})
			setLuaAnyTable(L, "args", []any{redisScriptArg})
			L.SetGlobal("upload_name", lua.LString(tc.scriptName))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_run_script("default", "", upload_name, keys, args)`)
			assert.NoError(t, err)

			resReturned := L.GetGlobal("result")
			errReturned := L.GetGlobal("err")

			if tc.expectedErr != "" {
				assert.NotEqual(t, lua.LNil, errReturned)
				assert.Contains(t, errReturned.String(), tc.expectedErr)
			} else {
				assert.Equal(t, lua.LNil, errReturned)
				assert.Equal(t, tc.expectedResult, resReturned.String())
			}

			if tc.expectedStoredSHA != "" {
				uploadedScript, ok := scriptsRepository.Get(tc.scriptName)
				assert.True(t, ok)
				assert.Equal(t, tc.expectedStoredSHA, uploadedScript.SHA1)
				assert.Equal(t, tc.uploadedScript.Source, uploadedScript.Source)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// namedUploadedScriptCases returns coverage for named custom Redis Lua scripts.
func namedUploadedScriptCases() []redisRunNamedUploadedScriptCase {
	return []redisRunNamedUploadedScriptCase{
		{
			name:           "ExistingSHASucceeds",
			scriptName:     customScriptName,
			uploadedScript: UploadedScript{SHA1: oldScriptSHA, Source: customScriptSource},
			expectedResult: mockRedisResult,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectEvalSha(oldScriptSHA, []string{redisScriptKey}, redisScriptArg).SetVal(mockRedisResult)
			},
		},
		{
			name:           "NoScriptRecovers",
			scriptName:     customScriptName,
			uploadedScript: UploadedScript{SHA1: oldScriptSHA, Source: customScriptSource},
			expectedResult: mockRedisResult,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectEvalSha(oldScriptSHA, []string{redisScriptKey}, redisScriptArg).SetErr(redisScriptMockError(noScriptRedisMessage))
				mock.ExpectScriptLoad(customScriptSource).SetVal(newScriptSHA)
				mock.ExpectEvalSha(newScriptSHA, []string{redisScriptKey}, redisScriptArg).SetVal(mockRedisResult)
			},
			expectedStoredSHA: newScriptSHA,
		},
		{
			name:        "MissingNameReturnsClearError",
			scriptName:  missingScriptName,
			expectedErr: missingScriptName,
		},
		{
			name:           "NoScriptRetryStopsAfterOneAttempt",
			scriptName:     customScriptName,
			uploadedScript: UploadedScript{SHA1: oldScriptSHA, Source: customScriptSource},
			expectedErr:    noScriptRedisPrefix,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectEvalSha(oldScriptSHA, []string{redisScriptKey}, redisScriptArg).SetErr(redisScriptMockError(noScriptRedisMessage))
				mock.ExpectScriptLoad(customScriptSource).SetVal(newScriptSHA)
				mock.ExpectEvalSha(newScriptSHA, []string{redisScriptKey}, redisScriptArg).SetErr(redisScriptMockError(noScriptRedisMessage))
			},
			expectedStoredSHA: newScriptSHA,
		},
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
			script:           customScriptSource,
			uploadScriptName: "mockScript1",
			expectErr:        false,
			expectedSHA:      "mockSHA",
			prepareRedisUpload: func(mock redismock.ClientMock) {
				mock.ExpectScriptLoad(customScriptSource).SetVal("mockSHA")
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
			resetScriptsRepository(t)

			L, mock := newRedisLuaTestState(t)
			tc.prepareRedisUpload(mock)

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

				if tc.uploadScriptName != "" {
					uploadedScript, ok := scriptsRepository.Get(tc.uploadScriptName)
					assert.True(t, ok)
					assert.Equal(t, tc.expectedSHA, uploadedScript.SHA1)
					assert.Equal(t, tc.script, uploadedScript.Source)
				}
			}

			// Check if everything expected was done
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestRedisRunScriptWithoutUploadNameUsesEval(t *testing.T) {
	resetScriptsRepository(t)

	L, mock := newRedisLuaTestState(t)
	mock.ExpectEval(customScriptSource, []string{redisScriptKey}, redisScriptArg).SetVal(mockRedisResult)

	setLuaStringTable(L, "keys", []string{redisScriptKey})
	setLuaAnyTable(L, "args", []any{redisScriptArg})
	L.SetGlobal("script", lua.LString(customScriptSource))

	err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_run_script("default", script, "", keys, args)`)
	assert.NoError(t, err)

	assert.Equal(t, lua.LNil, L.GetGlobal("err"))
	assert.Equal(t, mockRedisResult, L.GetGlobal("result").String())
	assert.NoError(t, mock.ExpectationsWereMet())
}

// newRedisLuaTestState creates a Lua state with the Redis module wired to a mock client.
func newRedisLuaTestState(t *testing.T) (*lua.LState, redismock.ClientMock) {
	t.Helper()

	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock conn.")
	}

	client := rediscli.NewTestClient(db)
	SetDefaultClient(client)

	testFile := &config.FileSettings{Server: &config.ServerSection{}}
	config.SetTestFile(testFile)
	util.SetDefaultConfigFile(testFile)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	L := lua.NewState()
	t.Cleanup(L.Close)

	ctx := context.Background()

	bindRedisRuntimeContextForTest(ctx, L)
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(ctx, testFile, client))

	return L, mock
}

// setLuaStringTable stores a Lua table with string values under the given global name.
func setLuaStringTable(L *lua.LState, name string, values []string) {
	tbl := L.NewTable()
	for _, value := range values {
		tbl.Append(lua.LString(value))
	}

	L.SetGlobal(name, tbl)
}

// setLuaAnyTable stores a Lua table after converting test values to Lua strings.
func setLuaAnyTable(L *lua.LState, name string, values []any) {
	tbl := L.NewTable()
	for _, value := range values {
		tbl.Append(lua.LString(value.(string)))
	}

	L.SetGlobal(name, tbl)
}

// resetScriptsRepository isolates tests from the package-level upload registry.
func resetScriptsRepository(t *testing.T) {
	t.Helper()

	scriptsRepository.mu.Lock()
	defer scriptsRepository.mu.Unlock()

	scriptsRepository.scripts = make(map[string]UploadedScript)
}

// hasStoredScript reports whether a non-empty uploaded script fixture was provided.
func hasStoredScript(script UploadedScript) bool {
	return strings.TrimSpace(script.SHA1) != "" || strings.TrimSpace(script.Source) != ""
}
