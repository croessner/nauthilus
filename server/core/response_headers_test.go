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

	a := &corepkg.AuthState{
		GUID:            "guid-nginx",
		Service:         definitions.ServNginx,
		Protocol:        config.NewProtocol("imap"),
		UsedBackendIP:   "10.0.0.5",
		UsedBackendPort: 993,
	}
	a.SetStatusCodes(a.Service)

	// No local cache hit in ctx by default; expect Miss header
	a.AuthOK(ctx)

	if got := w.Header().Get("Auth-Status"); got != "OK" {
		t.Fatalf("Auth-Status header = %q, want %q", got, "OK")
	}
	if got := w.Header().Get("X-Nauthilus-Session"); got != a.GUID {
		t.Fatalf("X-Nauthilus-Session = %q, want %q", got, a.GUID)
	}
	if got := w.Header().Get("X-Nauthilus-Memory-Cache"); got != "Miss" {
		t.Fatalf("X-Nauthilus-Memory-Cache = %q, want %q", got, "Miss")
	}
	if got := w.Header().Get("Auth-Server"); got != a.UsedBackendIP {
		t.Fatalf("Auth-Server = %q, want %q", got, a.UsedBackendIP)
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

	a := &corepkg.AuthState{
		GUID:                "guid-json",
		Service:             definitions.ServJSON,
		Protocol:            config.NewProtocol("imap"),
		SourcePassDBBackend: definitions.BackendLDAP,
		AccountField:        "uid",
		Attributes:          map[string][]any{"uid": {"alice"}},
	}
	a.SetStatusCodes(a.Service)

	a.AuthOK(ctx)

	if w.Code != a.StatusCodeOK {
		t.Fatalf("status code = %d, want %d", w.Code, a.StatusCodeOK)
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
