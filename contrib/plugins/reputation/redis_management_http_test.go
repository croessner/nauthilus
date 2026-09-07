//go:build reputation_integration

package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/custom"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type managementTokenValidator struct{}

// ValidateToken supplies authenticated test claims while the real host enforces audience and administrative scope.
func (managementTokenValidator) ValidateToken(_ context.Context, token string) (jwt.MapClaims, error) {
	scope := definitions.ScopeAuthenticate
	if token == "admin" {
		scope = definitions.ScopeAdmin
	}
	return jwt.MapClaims{"aud": definitions.AudienceBackchannelAPI, "sub": "verified-admin", "client_id": "operator-client",
		"scope": scope, definitions.ClaimTokenType: definitions.TokenTypeAccessToken}, nil
}

// managementRequestBuilder uses the same host request factory and authenticated caller projection as backchannel wiring.
func managementRequestBuilder(ctx *gin.Context, cfg config.File, _ pluginapi.HookDescriptor, caller custom.NativeHookCaller, body []byte) (pluginapi.HookRequest, error) {
	return pluginruntime.NewHookRequestFromHTTPRequest(ctx.Request, body, pluginruntime.HookRequestMetadata{
		Username: caller.Subject, OIDCCID: caller.ClientID, Authenticated: caller.Authenticated}, pluginruntime.WithSnapshotConfig(cfg)), nil
}

// managementHTTPFixture composes real registry, native runner, admin middleware, request factory and private primary storage.
func managementHTTPFixture(t *testing.T) (*gin.Engine, *Plugin) {
	t.Helper()
	_, facade := localReputationRedis(t)
	registry := pluginregistry.NewRegistry()
	plugin := NewPlugin()
	instance := transportModuleInstance(t, registry, config.PluginModule{Name: pluginName, Type: config.PluginModuleTypeGo, Config: testConfigMap(t)}, plugin.Register)
	instance.Plugin = plugin
	host := pluginruntime.NewHost(pluginruntime.WithConfig(pluginregistry.NewConfigView(testAdmissionMap())), pluginruntime.WithRedis(facade), pluginruntime.WithOpaqueIdentifierTagger(manifestTestTagger(t, false)))
	runner := pluginruntime.NewRunnerFromInstances(registry, []pluginloader.ModuleInstance{instance}, pluginruntime.WithHost(host))
	requireNoError(t, runner.Start(t.Context()))
	t.Cleanup(func() { requireNoError(t, runner.Stop(context.Background())) })
	bindings := make([]custom.NativeHook, 0, 3)
	for _, component := range runner.Hooks() {
		bindings = append(bindings, custom.NativeHook{Runner: runner, BuildRequest: managementRequestBuilder, Descriptor: component.HookDescriptor,
			QualifiedName: component.QualifiedName, ModuleName: component.ModuleName, ComponentName: component.LocalName})
	}
	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	router := gin.New()
	custom.New(configfx.NewProviderWithSnapshot(cfg), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, managementTokenValidator{}, custom.WithNativeHooks(bindings)).Register(router.Group("/api/v1"))
	return router, plugin
}

func TestReputationRedisManagementHTTPSeparatesObservationAndAdminAuthority(t *testing.T) {
	router, plugin := managementHTTPFixture(t)
	body := `{"kind":"ip","subject":"192.0.2.8","band":"blocked","reason":"incident","origin":"operator","audit_id":"http-change","ttl_seconds":3600}`
	for _, test := range []struct {
		token, body string
		status      int
	}{
		{"", body, http.StatusUnauthorized}, {"observer", body, http.StatusForbidden},
		{"admin", strings.TrimSuffix(body, "}") + `,"creator":"forged"}`, http.StatusBadRequest},
		{"admin", body, http.StatusOK},
	} {
		request := httptest.NewRequest(http.MethodPut, "/api/v1/custom/reputation/override", strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		if test.token != "" {
			request.Header.Set("Authorization", "Bearer "+test.token)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("management HTTP status=%d, wanted=%d: %s", response.Code, test.status, response.Body.String())
		}
		if test.status != http.StatusOK {
			if plugin.state.assess(t.Context(), subjectInput{kind: kindIP, value: "192.0.2.8"}, profileOperational).Override != overrideNone {
				t.Fatal("rejected caller changed state")
			}
			continue
		}
		var result managementView
		requireNoError(t, json.Unmarshal(response.Body.Bytes(), &result))
		if result.Audit == nil || result.Audit.Creator != "verified-admin" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("host actor or non-cacheable readback missing")
		}
		assertManagementResponseSchema(t, result)
	}
}

func TestReputationRedisManagementHTTPAllocationRemainsAvailableAfterDrain(t *testing.T) {
	router, plugin := managementHTTPFixture(t)
	for _, action := range []string{`{"action":"drain","reason":"key_rotation","origin":"operator","audit_id":"http-drain"}`, `{"action":"status"}`} {
		for _, token := range []string{"observer", "admin"} {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/custom/reputation/allocation", strings.NewReader(action))
			request.Header.Set("Content-Type", managementJSON)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			want := http.StatusOK
			if token == "observer" {
				want = http.StatusForbidden
			}
			if response.Code != want {
				t.Fatalf("allocation management status=%d wanted=%d: %s", response.Code, want, response.Body.String())
			}
		}
	}
	if plugin.state.ready.Load() {
		t.Fatal("administrative drain retained writer readiness")
	}
}
