package core_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	corepkg "github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"

	"net/http/httptest"

	"github.com/gin-gonic/gin"
)

func setupMinimalConfigForJSON(t *testing.T) {
	t.Helper()
	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	config.SetTestFile(cfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")
}

// TestResponseWriter_OK_JSONBodyMatchesGolden verifies the exact JSON body for
// a successful JSON response against a golden file.
func TestResponseWriter_OK_JSONBodyMatchesGolden(t *testing.T) {
	setupMinimalConfigForJSON(t)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	a := &corepkg.AuthState{
		GUID:                "guid-json-golden",
		Service:             definitions.ServJSON,
		Protocol:            config.NewProtocol("imap"),
		SourcePassDBBackend: definitions.BackendLDAP, // 2
		AccountField:        "account",
		TOTPSecretField:     "totp",
		Attributes:          map[string][]any{"dn": {"cn=user,dc=example,dc=org"}},
	}
	a.SetStatusCodes(a.Service)

	a.AuthOK(ctx)

	got := strings.TrimSpace(w.Body.String())

	// Load golden file
	goldenPath := filepath.Join("testdata", "response_json_ok.golden")
	expectBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read golden file: %v", err)
	}
	expect := strings.TrimSpace(string(expectBytes))

	if !bytes.Equal([]byte(got), []byte(expect)) {
		t.Fatalf("JSON body does not match golden.\nGot:    %s\nExpect: %s", got, expect)
	}
}
