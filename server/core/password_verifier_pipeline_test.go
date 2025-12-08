package core

import (
	stderrors "errors"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	serr "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/gin-gonic/gin"
)

func TestMain(m *testing.M) {
	// Provide a minimal test configuration to avoid panics from config.GetFile()
	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	InitPassDBResultPool()
	os.Exit(m.Run())
}

func TestVerifyPasswordPipeline_AllConfigErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	a := &AuthState{GUID: "cfg-err"}

	b0 := &PassDBMap{backend: definitions.BackendLDAP, fn: func(a *AuthState) (*PassDBResult, error) { return nil, serr.ErrLDAPConfig }}
	b1 := &PassDBMap{backend: definitions.BackendLua, fn: func(a *AuthState) (*PassDBResult, error) { return nil, serr.ErrLuaConfig }}

	_, err := VerifyPasswordPipeline(ctx, a, []*PassDBMap{b0, b1})
	if !stderrors.Is(err, serr.ErrAllBackendConfigError) {
		t.Fatalf("expected ErrAllBackendConfigError, got %v", err)
	}
}

func TestVerifyPasswordPipeline_NoBackends(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	a := &AuthState{GUID: "no-backends"}
	_, err := VerifyPasswordPipeline(ctx, a, []*PassDBMap{})
	if !stderrors.Is(err, serr.ErrAllBackendConfigError) {
		t.Fatalf("expected ErrAllBackendConfigError for no backends, got %v", err)
	}
}
