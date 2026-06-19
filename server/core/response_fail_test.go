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
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	corepkg "github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/encoding/cborcodec"
	"github.com/croessner/nauthilus/v3/server/log"

	"github.com/gin-gonic/gin"
)

const (
	httpI18NLockedKey      = "auth.policy.company.account_locked"
	httpI18NLockedText     = "Login failed because the account is locked."
	httpI18NLockedGerman   = "Anmeldung abgelehnt."
	httpI18NTempFailKey    = "auth.policy.company.account_tempfail"
	httpI18NTempFailText   = "Temporary company account check failed."
	httpI18NTempFailGerman = "Pruefung voruebergehend fehlgeschlagen."
	jsonErrorField         = "error"
	cborContentType        = "application/cbor"
)

func setupConfigForResponseTests(t *testing.T) {
	t.Helper()
	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	config.SetTestFile(cfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")
}

func newJSONResponseAuthState(
	ctx *gin.Context,
	cfg config.File,
	resolver localization.MessageResolver,
) *corepkg.AuthState {
	return newResponseAuthState(ctx, cfg, resolver, definitions.ServJSON)
}

func newResponseAuthState(
	ctx *gin.Context,
	cfg config.File,
	resolver localization.MessageResolver,
	service string,
) *corepkg.AuthState {
	deps := corepkg.AuthDeps{Cfg: cfg}
	if resolver != nil {
		deps.Resp = corepkg.NewDefaultResponseWriter(corepkg.ResponseDeps{
			Cfg:      cfg,
			Resolver: resolver,
		})
	}

	auth := corepkg.NewAuthStateFromContextWithDeps(ctx, deps).(*corepkg.AuthState)
	auth.Request.Service = service
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.SetStatusCodes(auth.Request.Service)

	return auth
}

func TestResponseWriter_Fail_JSONBodyNullAndHeaders(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	a := newJSONResponseAuthState(ctx, cfg, nil)
	a.Runtime.GUID = "guid-fail-json"

	// Trigger failure path
	a.AuthFail(ctx)

	if w.Code != a.Runtime.StatusCodeFail {
		t.Fatalf("status code = %d, want %d", w.Code, a.Runtime.StatusCodeFail)
	}
	// Expect Auth-Status header set to default password fail message
	if got := w.Header().Get("Auth-Status"); got != definitions.PasswordFail {
		t.Fatalf("Auth-Status header = %q, want %q", got, definitions.PasswordFail)
	}
	// Expect session header
	if got := w.Header().Get("X-Nauthilus-Session"); got != a.Runtime.GUID {
		t.Fatalf("X-Nauthilus-Session = %q, want %q", got, a.Runtime.GUID)
	}

	// Body should be JSON null
	var body any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if body != nil {
		t.Fatalf("expected JSON null body, got %#v", body)
	}
}

func TestResponseWriter_Fail_LocalizesPolicyI18NStatusFromAcceptLanguage(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)
	ctx.Request.Header.Set("Accept-Language", "de-DE,de;q=0.9,en;q=0.8")

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	resolver := &recordingHTTPStatusResolver{
		t: t,
		wantSelection: localization.StatusMessage{
			Text:    httpI18NLockedText,
			I18NKey: httpI18NLockedKey,
		},
		wantPreference: localization.LanguagePreference{
			Header: "de-DE,de;q=0.9,en;q=0.8",
		},
		resolved: localization.ResolvedStatusMessage{
			Text:      httpI18NLockedGerman,
			Language:  "de",
			Key:       httpI18NLockedKey,
			Localized: true,
		},
	}
	auth := newJSONResponseAuthState(ctx, cfg, resolver)
	auth.Runtime.GUID = "guid-fail-i18n-http"
	auth.Runtime.StatusMessage = httpI18NLockedText
	auth.Runtime.StatusMessageI18NKey = httpI18NLockedKey

	auth.AuthFail(ctx)

	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}

	if got := w.Header().Get("Auth-Status"); got != httpI18NLockedGerman {
		t.Fatalf("Auth-Status header = %q, want localized message", got)
	}

	if got := w.Header().Get("Content-Language"); got != "de" {
		t.Fatalf("Content-Language = %q, want de", got)
	}
}

func TestResponseWriter_Fail_KeepsPlainStatusMessageWithoutI18NKey(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)
	ctx.Request.Header.Set("Accept-Language", "de")

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	resolver := &recordingHTTPStatusResolver{t: t, failOnCall: true}
	auth := newJSONResponseAuthState(ctx, cfg, resolver)
	auth.Runtime.GUID = "guid-fail-plain-http"
	auth.Runtime.StatusMessage = "Plain policy denial"

	auth.AuthFail(ctx)

	if got := w.Header().Get("Auth-Status"); got != "Plain policy denial" {
		t.Fatalf("Auth-Status header = %q, want plain status message", got)
	}

	if got := w.Header().Get("Content-Language"); got != "" {
		t.Fatalf("Content-Language = %q, want empty header", got)
	}
}

func TestResponseWriter_Fail_UsesPolicyI18NFallbackWhenTranslationIsMissing(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)
	ctx.Request.Header.Set("Accept-Language", "de")

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	resolver := &recordingHTTPStatusResolver{
		t: t,
		wantSelection: localization.StatusMessage{
			Text:    httpI18NLockedText,
			I18NKey: httpI18NLockedKey,
		},
		wantPreference: localization.LanguagePreference{Header: "de"},
		resolved: localization.ResolvedStatusMessage{
			Text:         httpI18NLockedText,
			Language:     "de",
			Key:          httpI18NLockedKey,
			FallbackUsed: true,
		},
	}
	auth := newJSONResponseAuthState(ctx, cfg, resolver)
	auth.Runtime.GUID = "guid-fail-i18n-fallback-http"
	auth.Runtime.StatusMessage = httpI18NLockedText
	auth.Runtime.StatusMessageI18NKey = httpI18NLockedKey

	auth.AuthFail(ctx)

	if got := w.Header().Get("Auth-Status"); got != httpI18NLockedText {
		t.Fatalf("Auth-Status header = %q, want fallback message", got)
	}

	if got := w.Header().Get("Content-Language"); got != "de" {
		t.Fatalf("Content-Language = %q, want de", got)
	}
}

func TestResponseWriter_TempFail_JSONErrorBody(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	reason := "Temporary server problem"
	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	a := newJSONResponseAuthState(ctx, cfg, nil)
	a.Runtime.GUID = "guid-tempfail-json"

	a.AuthTempFail(ctx, reason)

	if w.Code != a.Runtime.StatusCodeInternalError {
		t.Fatalf("status code = %d, want %d", w.Code, a.Runtime.StatusCodeInternalError)
	}

	if got := w.Header().Get("Auth-Status"); got != reason {
		t.Fatalf("Auth-Status header = %q, want %q", got, reason)
	}
	if got := w.Header().Get("X-Nauthilus-Session"); got != a.Runtime.GUID {
		t.Fatalf("X-Nauthilus-Session = %q, want %q", got, a.Runtime.GUID)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if msg, ok := body[jsonErrorField].(string); !ok || msg != reason {
		t.Fatalf("expected error field %q, got %v (present=%v)", reason, body[jsonErrorField], ok)
	}
}

func TestResponseWriter_Fail_CBORBodyNullAndHeaders(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	auth := newResponseAuthState(ctx, cfg, nil, definitions.ServCBOR)
	auth.Runtime.GUID = "guid-fail-cbor"

	auth.AuthFail(ctx)

	if w.Code != auth.Runtime.StatusCodeFail {
		t.Fatalf("status code = %d, want %d", w.Code, auth.Runtime.StatusCodeFail)
	}

	if got := w.Header().Get("Content-Type"); got != cborContentType {
		t.Fatalf("Content-Type = %q, want %s", got, cborContentType)
	}

	if got := w.Header().Get("Auth-Status"); got != definitions.PasswordFail {
		t.Fatalf("Auth-Status header = %q, want %q", got, definitions.PasswordFail)
	}

	var body any
	if err := cborcodec.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid CBOR body: %v", err)
	}

	if body != nil {
		t.Fatalf("expected CBOR null body, got %#v", body)
	}
}

func TestResponseWriter_TempFail_CBORErrorBody(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	reason := "Temporary server problem"
	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	auth := newResponseAuthState(ctx, cfg, nil, definitions.ServCBOR)
	auth.Runtime.GUID = "guid-tempfail-cbor"

	auth.AuthTempFail(ctx, reason)

	if w.Code != auth.Runtime.StatusCodeInternalError {
		t.Fatalf("status code = %d, want %d", w.Code, auth.Runtime.StatusCodeInternalError)
	}

	if got := w.Header().Get("Content-Type"); got != cborContentType {
		t.Fatalf("Content-Type = %q, want %s", got, cborContentType)
	}

	if got := w.Header().Get("Auth-Status"); got != reason {
		t.Fatalf("Auth-Status header = %q, want %q", got, reason)
	}

	var body map[string]any
	if err := cborcodec.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid CBOR body: %v", err)
	}

	if msg, ok := body[jsonErrorField].(string); !ok || msg != reason {
		t.Fatalf("expected error field %q, got %v (present=%v)", reason, body[jsonErrorField], ok)
	}
}

func TestResponseWriter_TempFail_LocalizesPolicyI18NStatusWithPolicyLanguage(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)
	ctx.Request.Header.Set("Accept-Language", "en")

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	resolver := &recordingHTTPStatusResolver{
		t: t,
		wantSelection: localization.StatusMessage{
			Text:    httpI18NTempFailText,
			I18NKey: httpI18NTempFailKey,
		},
		wantPreference: localization.LanguagePreference{
			Policy: "de",
			Header: "en",
		},
		resolved: localization.ResolvedStatusMessage{
			Text:      httpI18NTempFailGerman,
			Language:  "de",
			Key:       httpI18NTempFailKey,
			Localized: true,
		},
	}
	auth := newJSONResponseAuthState(ctx, cfg, resolver)
	auth.Runtime.GUID = "guid-tempfail-i18n-http"
	auth.Runtime.StatusMessageI18NKey = httpI18NTempFailKey
	auth.Runtime.ResponseLanguage = "de"

	auth.AuthTempFail(ctx, httpI18NTempFailText)

	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}

	if got := w.Header().Get("Auth-Status"); got != httpI18NTempFailGerman {
		t.Fatalf("Auth-Status header = %q, want localized message", got)
	}

	if got := w.Header().Get("Content-Language"); got != "de" {
		t.Fatalf("Content-Language = %q, want de", got)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}

	if got, ok := body[jsonErrorField].(string); !ok || got != httpI18NTempFailGerman {
		t.Fatalf("error body = %v (present=%v), want localized message", body[jsonErrorField], ok)
	}
}

type recordingHTTPStatusResolver struct {
	t              *testing.T
	wantSelection  localization.StatusMessage
	wantPreference localization.LanguagePreference
	resolved       localization.ResolvedStatusMessage
	calls          int
	failOnCall     bool
}

func (r *recordingHTTPStatusResolver) ResolveStatusMessage(
	_ context.Context,
	selection localization.StatusMessage,
	preference localization.LanguagePreference,
) localization.ResolvedStatusMessage {
	r.calls++

	if r.failOnCall {
		r.t.Fatal("resolver should not be called for plain status messages")
	}

	if selection != r.wantSelection {
		r.t.Fatalf("selection = %#v, want %#v", selection, r.wantSelection)
	}

	if preference.Policy != r.wantPreference.Policy ||
		preference.Header != r.wantPreference.Header ||
		preference.Default != r.wantPreference.Default {
		r.t.Fatalf("preference = %#v, want %#v", preference, r.wantPreference)
	}

	return r.resolved
}
