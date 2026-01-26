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
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	corepkg "github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"

	"github.com/gin-gonic/gin"
)

func setupMinimalConfig(t *testing.T) {
	t.Helper()
	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	config.SetTestFile(cfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	// Ensure core default seams are initialized for legacy response/header paths.
	corepkg.SetDefaultConfigFile(config.GetFile())
	corepkg.SetDefaultEnvironment(config.GetEnvironment())
	corepkg.SetDefaultLogger(log.Logger)
}

func TestResponseWriter_OK_NginxSetsHeaders(t *testing.T) {
	setupMinimalConfig(t)

	// Enable backend server monitoring feature
	feat := &config.Feature{}
	_ = feat.Set(definitions.FeatureBackendServersMonitoring)
	cfg := config.GetFile().(*config.FileSettings)
	cfg.Server.Features = []*config.Feature{feat}

	// Ensure BackendServers reports >0 servers
	corepkg.BackendServers.Update([]*config.BackendServer{{Host: "127.0.0.1", Port: 993, Protocol: "imap"}})

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	deps := corepkg.AuthDeps{Cfg: cfg}
	a := corepkg.NewAuthStateFromContextWithDeps(ctx, deps).(*corepkg.AuthState)
	a.Request.Service = definitions.ServNginx
	a.Request.Protocol = config.NewProtocol("imap")
	a.Runtime.GUID = "guid-nginx"
	a.Runtime.UsedBackendIP = "10.0.0.5"
	a.Runtime.UsedBackendPort = 993
	a.SetStatusCodes(a.Request.Service)

	// No local cache hit in ctx by default; expect Miss header
	a.AuthOK(ctx)

	if got := w.Header().Get("Auth-Status"); got != "OK" {
		t.Fatalf("Auth-Status header = %q, want %q", got, "OK")
	}
	if got := w.Header().Get("X-Nauthilus-Session"); got != a.Runtime.GUID {
		t.Fatalf("X-Nauthilus-Session = %q, want %q", got, a.Runtime.GUID)
	}
	if got := w.Header().Get("X-Nauthilus-Memory-Cache"); got != "Miss" {
		t.Fatalf("X-Nauthilus-Memory-Cache = %q, want %q", got, "Miss")
	}
	if got := w.Header().Get("Auth-Server"); got != a.Runtime.UsedBackendIP {
		t.Fatalf("Auth-Server = %q, want %q", got, a.Runtime.UsedBackendIP)
	}
	if got := w.Header().Get("Auth-Port"); got != "993" {
		t.Fatalf("Auth-Port = %q, want %q", got, "993")
	}
}

func TestResponseWriter_OK_JSONBodyIncludesOK(t *testing.T) {
	setupMinimalConfig(t)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	cfgSettings := &config.FileSettings{Server: &config.ServerSection{}}
	deps := corepkg.AuthDeps{Cfg: cfgSettings}
	a := corepkg.NewAuthStateFromContextWithDeps(ctx, deps).(*corepkg.AuthState)
	a.Request.Service = definitions.ServJSON
	a.Request.Protocol = config.NewProtocol("imap")
	a.Runtime.GUID = "guid-json"
	a.Runtime.SourcePassDBBackend = definitions.BackendLDAP
	a.Runtime.AccountField = "uid"
	a.ReplaceAllAttributes(map[string][]any{"uid": {"alice"}})
	a.SetStatusCodes(a.Request.Service)

	a.AuthOK(ctx)

	if w.Code != a.Runtime.StatusCodeOK {
		t.Fatalf("status code = %d, want %d", w.Code, a.Runtime.StatusCodeOK)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}

	if okVal, ok := body["ok"]; !ok || okVal != true {
		t.Fatalf("expected ok=true field, got %v (present=%v)", okVal, ok)
	}
	if af, ok := body["account_field"].(string); !ok || af != "uid" {
		t.Fatalf("expected account_field=uid, got %v (present=%v)", body["account_field"], ok)
	}
	if _, ok := body["attributes"].(map[string]any); !ok {
		t.Fatalf("expected attributes field to be an object, got %T", body["attributes"])
	}
}
