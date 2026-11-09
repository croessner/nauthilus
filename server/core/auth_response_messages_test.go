// Copyright (C) 2026 Christian Roessner
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

package core

import (
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/definitions"

	"github.com/gin-gonic/gin"
)

const (
	authResponseTestFailure  = "Login rejected by example.test"
	authResponseTestTempFail = "Service busy at example.test"
)

// TestAuthResponseSettingsClientStatusMessage pins which texts the operator overrides replace.
func TestAuthResponseSettingsClientStatusMessage(t *testing.T) {
	configured := AuthResponseSettings{FailureMessage: authResponseTestFailure, TempFailMessage: authResponseTestTempFail}
	builtIn := NewAuthResponseSettings(&config.FileSettings{Server: &config.ServerSection{}})

	tests := []struct {
		name     string
		settings AuthResponseSettings
		text     string
		key      string
		wantText string
		wantKey  string
	}{
		{name: "failure override", settings: configured, text: definitions.PasswordFail,
			wantText: authResponseTestFailure, wantKey: authResponseTestFailure},
		{name: "tempfail override", settings: configured, text: definitions.TempFailDefault,
			wantText: authResponseTestTempFail, wantKey: authResponseTestTempFail},
		{name: "override keeps a selected i18n key", settings: configured, text: definitions.PasswordFail,
			key: "auth.denied", wantText: authResponseTestFailure, wantKey: "auth.denied"},
		{name: "specific tempfail reason stays", settings: configured, text: definitions.TempFailNoTLS,
			wantText: definitions.TempFailNoTLS},
		{name: "policy text stays", settings: configured, text: "Account locked", key: "account.locked",
			wantText: "Account locked", wantKey: "account.locked"},
		{name: "built-in defaults are no override", settings: builtIn, text: definitions.PasswordFail,
			wantText: definitions.PasswordFail},
		{name: "uncaptured settings are no override", text: definitions.TempFailDefault,
			wantText: definitions.TempFailDefault},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			text, key := test.settings.ClientStatusMessage(test.text, test.key)
			if text != test.wantText || key != test.wantKey {
				t.Fatalf("ClientStatusMessage(%q, %q) = %q/%q, want %q/%q", test.text, test.key, text, key,
					test.wantText, test.wantKey)
			}
		})
	}
}

// TestHTTPAuthResponseRendererAppliesOperatorResponseMessages renders configured texts for default deny and tempfail.
func TestHTTPAuthResponseRendererAppliesOperatorResponseMessages(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deps := httpAuthResponseTestDeps()
	deps.Cfg.GetServer().AuthResponse = config.AuthResponseSection{
		FailureMessage:  authResponseTestFailure,
		TempFailMessage: authResponseTestTempFail,
	}

	tests := []struct {
		name     string
		outcome  AuthOutcome
		wantText string
	}{
		{name: "selected default deny", outcome: AuthOutcome{Decision: AuthDecisionFail,
			StatusMessage: definitions.PasswordFail}, wantText: authResponseTestFailure},
		{name: "empty deny falls back to override", outcome: AuthOutcome{Decision: AuthDecisionFail},
			wantText: authResponseTestFailure},
		{name: "selected default tempfail", outcome: AuthOutcome{Decision: AuthDecisionTempFail,
			StatusMessage: definitions.TempFailDefault, Error: definitions.TempFailDefault}, wantText: authResponseTestTempFail},
		{name: "empty tempfail falls back to override", outcome: AuthOutcome{Decision: AuthDecisionTempFail},
			wantText: authResponseTestTempFail},
		{name: "captured settings win over renderer config", outcome: AuthOutcome{Decision: AuthDecisionFail,
			StatusMessage: definitions.PasswordFail, ResponseSettings: AuthResponseSettings{
				Captured: true, FailureMessage: "Captured rejection"}}, wantText: "Captured rejection"},
		{name: "specific tempfail reason stays", outcome: AuthOutcome{Decision: AuthDecisionTempFail,
			StatusMessage: definitions.TempFailNoTLS}, wantText: definitions.TempFailNoTLS},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			renderer := NewHTTPAuthResponseRenderer(deps)
			ctx, recorder := newHTTPAuthResponseTestContext(http.MethodGet, "/api/v1/auth/header")
			outcome := test.outcome

			renderer.RenderAuth(ctx, AuthInput{Mode: AuthModeAuthenticate, Service: definitions.ServHeader}, &outcome)

			if got := recorder.Header().Get("Auth-Status"); got != test.wantText {
				t.Fatalf("Auth-Status = %q, want %q", got, test.wantText)
			}
		})
	}
}

// TestHTTPAuthResponseRendererLocalizesOperatorResponseMessage resolves a configured text through its own i18n key.
func TestHTTPAuthResponseRendererLocalizesOperatorResponseMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	resolver := &httpAuthResponseRecordingResolver{
		resolved: localization.ResolvedStatusMessage{Text: "Anmeldung abgelehnt", Language: "de", Localized: true},
	}
	deps := httpAuthResponseTestDeps()
	deps.Resolver = resolver

	renderer := NewHTTPAuthResponseRenderer(deps)
	ctx, recorder := newHTTPAuthResponseTestContext(http.MethodGet, "/api/v1/auth/header")
	outcome := &AuthOutcome{
		Decision:         AuthDecisionFail,
		StatusMessage:    definitions.PasswordFail,
		ResponseSettings: AuthResponseSettings{Captured: true, FailureMessage: authResponseTestFailure},
	}

	renderer.RenderAuth(ctx, AuthInput{Mode: AuthModeAuthenticate, Service: definitions.ServHeader}, outcome)

	if resolver.selection.I18NKey != authResponseTestFailure || resolver.selection.Text != authResponseTestFailure {
		t.Fatalf("resolver selection = %#v, want the operator text as text and key", resolver.selection)
	}

	if got := recorder.Header().Get("Auth-Status"); got != "Anmeldung abgelehnt" {
		t.Fatalf("Auth-Status = %q, want the localized operator text", got)
	}
}
