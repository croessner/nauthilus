// Copyright (C) 2024-2025 Christian Rößner
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

package auth

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestDefaultLuaSubject_OverridesAccountField(t *testing.T) { //nolint:funlen
	gin.SetMode(gin.TestMode)

	cfg := prepareLuaSubjectTestConfig(t)
	program := newLuaSubjectTestProgram(t, "account_field", luaSubjectFixturePath(t, "account_field.lua"))

	redisDB, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(redisDB)

	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{
		Cfg:    cfg,
		Logger: log.GetLogger(),
		Redis:  redisClient,
	}).(*core.AuthState)

	auth.Runtime.GUID = "guid-1"
	auth.Runtime.StartTime = time.Now()
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Request.Username = "user@example.com"
	auth.Request.Password = secret.New("secret")
	auth.Request.ClientIP = "127.0.0.1"
	auth.Runtime.AccountField = "rnsMSDovecotUser"
	auth.ReplaceAllAttributes(map[string][]any{
		"rnsMSDovecotUser": {"user@example.com"},
	})

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	result := program.execute(ctx, auth.View(), &core.PassDBResult{})
	if result != definitions.AuthResultFail {
		t.Fatalf("expected AuthResultFail, got %v", result)
	}

	attrs, ok := auth.GetAttribute("Account-Field")
	if !ok || len(attrs) == 0 {
		t.Fatalf("expected Account-Field attribute to be set")
	}

	value, ok := attrs[definitions.LDAPSingleValue].(string)
	if !ok {
		t.Fatalf("expected Account-Field attribute to be string")
	}

	if value != definitions.MetaUserAccount {
		t.Fatalf("expected Account-Field to be %q, got %q", definitions.MetaUserAccount, value)
	}
}

func TestDefaultLuaSubject_MergesGroupsFromBackendResult(t *testing.T) {
	auth, ctx := newLuaSubjectGroupMergeTestAuth(t)
	program := newLuaSubjectTestProgram(t, "groups_apply", luaSubjectFixturePath(t, "groups_apply.lua"))
	passDBResult := &core.PassDBResult{}

	result := program.execute(ctx, auth.View(), passDBResult)
	if result != definitions.AuthResultFail {
		t.Fatalf("expected AuthResultFail, got %v", result)
	}

	assertLuaSubjectMergedGroups(t, auth, passDBResult)
}

func TestDefaultLuaSubjectAnalyzeSourceIgnoresAmbientSourceCollection(t *testing.T) {
	auth, ctx := newLuaSubjectGroupMergeTestAuth(t)
	program := newLuaSubjectTestProgramFromSource(t, "captured_subject", `
function nauthilus_call_subject(_request)
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)

	passDBResult := &core.PassDBResult{Authenticated: true, UserFound: true}

	result := program.execute(ctx, auth.View(), passDBResult)
	if result != definitions.AuthResultOK {
		t.Fatalf("captured subject result = %v, want %v", result, definitions.AuthResultOK)
	}

	if groups := auth.GetGroups(); len(groups) != 1 || groups[0] != "Existing" {
		t.Fatalf("captured subject groups = %v, want ambient source untouched", groups)
	}
}

// newLuaSubjectGroupMergeTestAuth prepares AuthState for Lua subject group merge tests.
func newLuaSubjectGroupMergeTestAuth(t *testing.T) (*core.AuthState, *gin.Context) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	cfg := prepareLuaSubjectTestConfig(t)

	redisDB, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(redisDB)

	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{
		Cfg:    cfg,
		Logger: log.GetLogger(),
		Redis:  redisClient,
	}).(*core.AuthState)
	auth.Runtime.GUID = "guid-2"
	auth.Runtime.StartTime = time.Now()
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Request.Username = "user@example.com"
	auth.Request.Password = secret.New("secret")
	auth.Request.ClientIP = "127.0.0.1"
	auth.SetResolvedGroups([]string{"Existing"}, nil)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	return auth, ctx
}

// prepareLuaSubjectTestConfig installs only non-policy dependencies for one subject test.
func prepareLuaSubjectTestConfig(t *testing.T) *config.FileSettings {
	t.Helper()

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "nt:",
			},
		},
	}

	envCfg := config.NewTestEnvironmentConfig()
	config.SetTestEnvironmentConfig(envCfg)
	config.SetTestFile(cfg)
	util.SetDefaultEnvironment(envCfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	return cfg
}

// assertLuaSubjectMergedGroups verifies merged auth and passDB group state.
func assertLuaSubjectMergedGroups(t *testing.T, auth *core.AuthState, passDBResult *core.PassDBResult) {
	t.Helper()

	if got := auth.GetGroups(); len(got) != 3 || got[0] != "Developer" || got[1] != "Existing" || got[2] != "Ops" {
		t.Fatalf("unexpected merged groups on auth state: %v", got)
	}

	if got := passDBResult.Groups; len(got) != 3 || got[0] != "Developer" || got[1] != "Existing" || got[2] != "Ops" {
		t.Fatalf("unexpected merged groups on passDBResult: %v", got)
	}

	if got := passDBResult.GroupDistinguishedNames; len(got) != 1 || got[0] != "cn=Developer,ou=groups,dc=example,dc=org" {
		t.Fatalf("unexpected group_dns on passDBResult: %v", got)
	}
}

func TestDefaultLuaSubjectAnalyzeSourceSkipsCanceledRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := prepareLuaSubjectTestConfig(t)
	program := newLuaSubjectTestProgramFromSource(t, "canceled_subject", `
function nauthilus_call_subject(_request)
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)

	reqCtx, cancel := context.WithCancel(context.Background())
	cancel()

	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest("POST", "/auth", nil).WithContext(reqCtx)
	redisDB, _ := redismock.NewClientMock()

	auth := core.NewAuthStateFromContextWithDeps(ctx, core.AuthDeps{
		Cfg:    cfg,
		Logger: log.GetLogger(),
		Redis:  rediscli.NewTestClient(redisDB),
	}).(*core.AuthState)

	auth.Runtime.GUID = "guid-canceled-subject"
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Request.Service = definitions.ServNginx
	auth.Request.Username = "user@example.com"

	result := program.execute(ctx, auth.View(), &core.PassDBResult{})
	if result != definitions.AuthResultTempFail {
		t.Fatalf("expected AuthResultTempFail, got %v", result)
	}
}

type luaSubjectTestProgram struct {
	prototype *lua.FunctionProto
	pools     *vmpool.Manager
	modules   *luaseal.Modules
	name      string
	poolKey   vmpool.PoolKey
}

// execute invokes the exact compiled source and generation-owned test resources.
func (p *luaSubjectTestProgram) execute(
	ctx *gin.Context,
	view *core.StateView,
	passDBResult *core.PassDBResult,
) definitions.AuthResult {
	return (DefaultLuaSubject{}).AnalyzeSource(
		ctx,
		view,
		passDBResult,
		p.name,
		p.prototype,
		p.pools,
		p.poolKey,
		p.modules,
	)
}

// newLuaSubjectTestProgram captures and compiles one immutable subject source for a test generation.
func newLuaSubjectTestProgram(t *testing.T, name string, scriptPath string) *luaSubjectTestProgram {
	t.Helper()

	snapshot, err := config.CaptureArtifactSnapshot(config.ArtifactSnapshotSpec{Paths: []string{scriptPath}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	t.Cleanup(snapshot.Release)

	modules, err := luaseal.CaptureSnapshot(nil, snapshot)
	if err != nil {
		t.Fatalf("CaptureSnapshot() error = %v", err)
	}

	source, err := snapshot.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read captured Lua subject source: %v", err)
	}
	defer clear(source)

	if err = modules.ValidateSource(scriptPath, source, luaseal.PolicyProfileSubject); err != nil {
		t.Fatalf("validate captured Lua subject source: %v", err)
	}

	prototype, err := lualib.CompileLuaSource(scriptPath, source)
	if err != nil {
		t.Fatalf("CompileLuaSource() error = %v", err)
	}

	pools := vmpool.NewManager()
	poolKey := vmpool.PoolKey("test:core-auth:subject:" + t.Name() + ":" + name)
	t.Cleanup(func() {
		if deleteErr := pools.Delete(poolKey); deleteErr != nil {
			t.Errorf("delete Lua subject VM pool %q: %v", poolKey, deleteErr)
		}
	})

	return &luaSubjectTestProgram{
		prototype: prototype,
		pools:     pools,
		modules:   modules,
		name:      name,
		poolKey:   poolKey,
	}
}

// newLuaSubjectTestProgramFromSource persists an inline fixture before immutable candidate capture.
func newLuaSubjectTestProgramFromSource(t *testing.T, name string, source string) *luaSubjectTestProgram {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), name+".lua")
	if err := os.WriteFile(scriptPath, []byte(source), 0o600); err != nil {
		t.Fatalf("write Lua subject source: %v", err)
	}

	return newLuaSubjectTestProgram(t, name, scriptPath)
}

// luaSubjectFixturePath resolves one checked-in subject fixture from this package.
func luaSubjectFixturePath(t *testing.T, name string) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}

	return filepath.Clean(filepath.Join(wd, "..", "..", "lualib", "subject", "testdata", name))
}
