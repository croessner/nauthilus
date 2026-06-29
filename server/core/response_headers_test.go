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
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	corepkg "github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/encoding/cborcodec"
	"github.com/croessner/nauthilus/v3/server/log"

	"github.com/gin-gonic/gin"
)

const (
	sensitiveResponseTOTPField     = "ldap_totp_secret"
	sensitiveResponseRecoveryField = "ldap_totp_recovery"
	sensitiveResponseTOTPValue     = "fake-totp-seed-not-for-output"
	sensitiveResponseRecoveryValue = "fake-recovery-code-not-for-output"
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

func TestAuthResponseSuppressesSensitiveAttributes(t *testing.T) {
	for _, service := range []string{definitions.ServJSON, definitions.ServCBOR} {
		t.Run(service, func(t *testing.T) {
			auth, body := runAuthResponseBody(t, service, map[string][]any{
				"uid":                          {"alice"},
				sensitiveResponseTOTPField:     {sensitiveResponseTOTPValue},
				sensitiveResponseRecoveryField: {sensitiveResponseRecoveryValue},
			})

			assertAuthResponseOmitsSensitiveFields(t, body, auth.Runtime.TOTPSecretField, sensitiveResponseTOTPValue, sensitiveResponseRecoveryValue)
		})
	}
}

func TestAuthResponsePreservesSafeAttributes(t *testing.T) {
	auth, body := runAuthResponseBody(t, definitions.ServJSON, map[string][]any{
		"uid":         {"alice"},
		"displayName": {"Alice Example"},
	})

	attrs, ok := body["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("attributes = %T, want object", body["attributes"])
	}

	if got := firstStringAttribute(attrs, "uid"); got != "alice" {
		t.Fatalf("uid attribute = %q, want alice", got)
	}

	if got := firstStringAttribute(attrs, "displayName"); got != "Alice Example" {
		t.Fatalf("displayName attribute = %q, want Alice Example", got)
	}

	if got, _ := body["totp_secret_field"].(string); got != "" {
		t.Fatalf("totp_secret_field = %q, want empty", got)
	}

	if auth.Runtime.GUID == "" {
		t.Fatal("auth runtime GUID unexpectedly empty")
	}
}

func TestHeaderSuppressesSensitiveAttributes(t *testing.T) {
	setupMinimalConfig(t)

	w, ctx, auth := newHeaderResponseAuthState(t, definitions.ServHeader)
	auth.Runtime.TOTPSecretField = sensitiveResponseTOTPField
	auth.Runtime.TOTPRecoveryField = sensitiveResponseRecoveryField
	auth.ReplaceAllAttributes(map[string][]any{
		"uid":                          {"alice"},
		sensitiveResponseTOTPField:     {sensitiveResponseTOTPValue},
		sensitiveResponseRecoveryField: {sensitiveResponseRecoveryValue},
	})

	auth.AuthOK(ctx)

	for _, header := range []string{
		"X-Nauthilus-" + sensitiveResponseTOTPField,
		"X-Nauthilus-" + sensitiveResponseRecoveryField,
	} {
		if got := w.Header().Get(header); got != "" {
			t.Fatalf("%s = %q, want empty", header, got)
		}
	}
}

func TestHeaderPreservesSafeAttributes(t *testing.T) {
	setupMinimalConfig(t)

	w, ctx, auth := newHeaderResponseAuthState(t, definitions.ServHeader)
	auth.ReplaceAllAttributes(map[string][]any{
		"uid":         {"alice"},
		"displayName": {"Alice Example"},
	})

	auth.AuthOK(ctx)

	if got := w.Header().Get("X-Nauthilus-uid"); got != "alice" {
		t.Fatalf("X-Nauthilus-uid = %q, want alice", got)
	}

	if got := w.Header().Get("X-Nauthilus-displayName"); got != "Alice Example" {
		t.Fatalf("X-Nauthilus-displayName = %q, want Alice Example", got)
	}
}

func TestResponseWriter_OK_NginxSetsHeaders(t *testing.T) {
	setupMinimalConfig(t)

	// Enable backend health-check service
	feat := &config.RuntimeModule{}
	_ = feat.Set(definitions.ServiceBackendHealthChecks)
	cfg := config.GetFile().(*config.FileSettings)
	cfg.Server.RuntimeModules = []*config.RuntimeModule{feat}

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

func runAuthResponseBody(t *testing.T, service string, attributes map[string][]any) (*corepkg.AuthState, map[string]any) {
	t.Helper()
	setupMinimalConfig(t)

	w, ctx, auth := newHeaderResponseAuthState(t, service)
	auth.Runtime.SourcePassDBBackend = definitions.BackendLDAP
	auth.Runtime.AccountField = "uid"
	auth.Runtime.TOTPSecretField = sensitiveResponseTOTPField
	auth.Runtime.TOTPRecoveryField = sensitiveResponseRecoveryField
	auth.ReplaceAllAttributes(attributes)

	auth.AuthOK(ctx)

	if w.Code != auth.Runtime.StatusCodeOK {
		t.Fatalf("status code = %d, want %d", w.Code, auth.Runtime.StatusCodeOK)
	}

	var body map[string]any

	switch service {
	case definitions.ServCBOR:
		if err := cborcodec.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("invalid CBOR body: %v", err)
		}
	default:
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("invalid JSON body: %v", err)
		}
	}

	return auth, body
}

func newHeaderResponseAuthState(t *testing.T, service string) (*httptest.ResponseRecorder, *gin.Context, *corepkg.AuthState) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	cfgSettings := &config.FileSettings{Server: &config.ServerSection{}}
	deps := corepkg.AuthDeps{Cfg: cfgSettings}
	auth := corepkg.NewAuthStateFromContextWithDeps(ctx, deps).(*corepkg.AuthState)
	auth.Request.Service = service
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Runtime.GUID = "guid-" + strings.ToLower(service)
	auth.SetStatusCodes(auth.Request.Service)

	return w, ctx, auth
}

func assertAuthResponseOmitsSensitiveFields(t *testing.T, body map[string]any, sensitiveNamesAndValues ...string) {
	t.Helper()

	bodyText := fmt.Sprintf("%#v", body)

	for _, sensitive := range sensitiveNamesAndValues {
		if strings.Contains(bodyText, sensitive) {
			t.Fatalf("auth response exposed sensitive value %q in %s", sensitive, bodyText)
		}
	}

	for _, name := range []string{sensitiveResponseTOTPField, sensitiveResponseRecoveryField} {
		if attributeMapContainsKey(body["attributes"], name) {
			t.Fatalf("attributes unexpectedly included sensitive key %q: %#v", name, body["attributes"])
		}
	}
}

func attributeMapContainsKey(value any, name string) bool {
	switch typed := value.(type) {
	case map[string]any:
		_, found := typed[name]

		return found
	case map[interface{}]interface{}:
		_, found := typed[name]

		return found
	default:
		return false
	}
}

func firstStringAttribute(attrs map[string]any, name string) string {
	values, ok := attrs[name].([]any)
	if !ok || len(values) == 0 {
		return ""
	}

	value, _ := values[0].(string)

	return value
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

	if attrs, ok := body["attributes"]; !ok || attrs == nil {
		t.Fatalf("expected attributes field to be present, got %T", body["attributes"])
	}
}

func TestResponseWriter_OK_CBORBodyIncludesOK(t *testing.T) {
	setupMinimalConfig(t)

	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	cfgSettings := &config.FileSettings{Server: &config.ServerSection{}}
	deps := corepkg.AuthDeps{Cfg: cfgSettings}
	auth := corepkg.NewAuthStateFromContextWithDeps(ctx, deps).(*corepkg.AuthState)
	auth.Request.Service = definitions.ServCBOR
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Runtime.GUID = "guid-cbor"
	auth.Runtime.SourcePassDBBackend = definitions.BackendLDAP
	auth.Runtime.AccountField = "uid"
	auth.ReplaceAllAttributes(map[string][]any{"uid": {"alice"}})
	auth.SetStatusCodes(auth.Request.Service)

	auth.AuthOK(ctx)

	if w.Code != auth.Runtime.StatusCodeOK {
		t.Fatalf("status code = %d, want %d", w.Code, auth.Runtime.StatusCodeOK)
	}

	if got := w.Header().Get("Content-Type"); got != cborContentType {
		t.Fatalf("Content-Type = %q, want %s", got, cborContentType)
	}

	var body map[string]any
	if err := cborcodec.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid CBOR body: %v", err)
	}

	if okVal, ok := body["ok"].(bool); !ok || !okVal {
		t.Fatalf("expected ok=true field, got %v (present=%v)", okVal, ok)
	}

	if af, ok := body["account_field"].(string); !ok || af != "uid" {
		t.Fatalf("expected account_field=uid, got %v (present=%v)", body["account_field"], ok)
	}

	if attrs, ok := body["attributes"]; !ok || attrs == nil {
		t.Fatalf("expected attributes field to be present, got %T", body["attributes"])
	}
}
