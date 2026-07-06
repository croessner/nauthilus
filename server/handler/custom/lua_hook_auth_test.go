package custom

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/lualib/hook"
	"github.com/croessner/nauthilus/v3/server/secret"

	"github.com/gin-gonic/gin"
)

const (
	luaHookAuthTestClient = "hook-client"
	luaHookAuthTestSecret = "hook-secret"
)

func TestLuaHookAuthHandlerAllowsValidBackchannelBasicAuth(t *testing.T) {
	router := newLuaHookAuthTestRouter(t, luaHookAuthTestConfig{
		location: "/basic-hook",
		method:   http.MethodGet,
	})

	rec := performLuaHookAuthRequest(router, http.MethodGet, "/api/v1/custom/basic-hook", luaHookAuthTestClient, luaHookAuthTestSecret)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}

	if got := rec.Body.String(); got != `{"executed":"basic-hook"}` {
		t.Fatalf("body = %s, want executed Lua hook result", got)
	}
}

func TestLuaHookAuthHandlerRejectsInvalidBackchannelBasicAuth(t *testing.T) {
	router := newLuaHookAuthTestRouter(t, luaHookAuthTestConfig{
		location: "/basic-hook",
		method:   http.MethodGet,
	})

	rec := performLuaHookAuthRequest(router, http.MethodGet, "/api/v1/custom/basic-hook", luaHookAuthTestClient, "wrong-secret")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s, want 401", rec.Code, rec.Body.String())
	}

	if got := rec.Body.String(); got != `{"error":"authentication required"}` {
		t.Fatalf("body = %s, want authentication required error", got)
	}
}

func TestLuaHookAuthHandlerAllowsExplicitPublicHookWithoutBasicAuth(t *testing.T) {
	router := newLuaHookAuthTestRouter(t, luaHookAuthTestConfig{
		location: "/public-hook",
		method:   http.MethodGet,
		public:   true,
	})

	rec := performLuaHookAuthRequest(router, http.MethodGet, "/api/v1/custom/public-hook", "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}

	if got := rec.Body.String(); got != `{"executed":"public-hook"}` {
		t.Fatalf("body = %s, want executed Lua hook result", got)
	}
}

type luaHookAuthTestConfig struct {
	location string
	method   string
	public   bool
}

// newLuaHookAuthTestRouter registers one Lua custom hook with isolated test configuration.
func newLuaHookAuthTestRouter(t *testing.T, testCfg luaHookAuthTestConfig) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)
	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix:      "t:",
				NegCacheTTL: time.Hour,
			},
			BasicAuth: config.BasicAuth{
				Enabled:  true,
				Username: luaHookAuthTestClient,
				Password: secret.New(luaHookAuthTestSecret),
			},
		},
		Lua: &config.LuaSection{
			Hooks: []config.LuaHooks{
				{
					Location:   testCfg.location,
					Method:     testCfg.method,
					ScriptPath: writeLuaHookAuthTestScript(t, testCfg.location),
					Public:     testCfg.public,
				},
			},
		},
	}
	config.SetTestFile(cfg)

	if err := hook.PreCompileLuaHooks(cfg); err != nil {
		t.Fatalf("PreCompileLuaHooks() error = %v", err)
	}

	t.Cleanup(func() {
		if err := hook.PreCompileLuaHooks(&config.FileSettings{}); err != nil {
			t.Fatalf("reset Lua hook registry: %v", err)
		}

		aliasDispatcher.Lock()
		aliasDispatcher.handler = nil
		aliasDispatcher.nativeAliases = nil
		aliasDispatcher.Unlock()
	})

	router := gin.New()
	handler := New(
		configfx.NewProviderWithSnapshot(cfg),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		nil,
	)
	handler.Register(router.Group("/api/v1"))

	return router
}

// writeLuaHookAuthTestScript writes a deterministic Lua hook returning its executed marker.
func writeLuaHookAuthTestScript(t *testing.T, location string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "hook.lua")
	content := []byte(`function nauthilus_run_hook(request)
	return { executed = "` + location[1:] + `" }
end
`)

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write Lua hook script: %v", err)
	}

	return path
}

// performLuaHookAuthRequest executes one Lua custom hook request with optional Basic Auth.
func performLuaHookAuthRequest(router http.Handler, method string, path string, username string, password string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, http.NoBody)
	req.RemoteAddr = "192.0.2.20:12345"

	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}

	router.ServeHTTP(rec, req)

	return rec
}
