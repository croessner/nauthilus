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

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	deps := corepkg.AuthDeps{Cfg: cfg}
	a := corepkg.NewAuthStateFromContextWithDeps(ctx, deps).(*corepkg.AuthState)
	a.Request.Service = definitions.ServJSON
	a.Request.Protocol = config.NewProtocol("imap")
	a.Runtime.GUID = "guid-json-golden"
	a.Runtime.SourcePassDBBackend = definitions.BackendLDAP
	a.Runtime.AccountField = "account"
	a.Runtime.TOTPSecretField = "totp"
	a.ReplaceAllAttributes(map[string][]any{"dn": {"cn=user,dc=example,dc=org"}})
	a.SetStatusCodes(a.Request.Service)

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
