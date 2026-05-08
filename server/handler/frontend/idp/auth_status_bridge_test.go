// Copyright (C) 2026 Christian Rößner
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

package idp

import (
	"context"
	stderrors "errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/core/localization"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	idpservice "github.com/croessner/nauthilus/server/idp"
	"github.com/gin-gonic/gin"
)

const (
	authStatusBridgeKey         = "auth.policy.company.account_blocked"
	authStatusBridgeFallback    = "Login failed because the account is locked."
	authStatusBridgeGermanText  = "Anmeldung gesperrt."
	authStatusBridgeGenericText = "Invalid login or password"
)

func TestIDPAuthFailureMessageUsesExplicitUILanguageBeforePolicyLanguage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	resolver := &recordingIDPStatusResolver{
		resolved: localization.ResolvedStatusMessage{
			Text:      authStatusBridgeGermanText,
			Language:  "de",
			Localized: true,
			Key:       authStatusBridgeKey,
		},
	}
	d := authStatusBridgeDeps(resolver)
	ctx := authStatusBridgeContext("/login/de", "en-US,en;q=0.9")
	ctx.Params = append(ctx.Params, gin.Param{Key: "languageTag", Value: "de"})

	err := idpservice.NewAuthFailureError(
		stderrors.New("policy rejected login"),
		idpservice.AuthFailureStatus{
			StatusMessage:    authStatusBridgeFallback,
			I18NKey:          authStatusBridgeKey,
			ResponseLanguage: "fr",
			PolicyTerminal:   true,
		},
	)

	message := renderIDPAuthFailureMessage(ctx, d, err, authStatusBridgeGenericText)

	if message != authStatusBridgeGermanText {
		t.Fatalf("message = %q, want %q", message, authStatusBridgeGermanText)
	}

	if resolver.preference.Explicit != "de" {
		t.Fatalf("explicit language = %q, want de", resolver.preference.Explicit)
	}

	if resolver.preference.Policy != "fr" {
		t.Fatalf("policy language = %q, want fr", resolver.preference.Policy)
	}

	if resolver.preference.Header != "en-US,en;q=0.9" {
		t.Fatalf("header language = %q, want request Accept-Language", resolver.preference.Header)
	}
}

func TestIDPAuthFailureMessageKeepsGenericFallbackWithoutPolicyI18N(t *testing.T) {
	gin.SetMode(gin.TestMode)

	resolver := &recordingIDPStatusResolver{failOnCall: true}
	d := authStatusBridgeDeps(resolver)
	ctx := authStatusBridgeContext("/login", "de-DE,de;q=0.9")

	err := idpservice.NewAuthFailureError(
		stderrors.New("plain login failed"),
		idpservice.AuthFailureStatus{
			StatusMessage: authStatusBridgeFallback,
		},
	)

	message := renderIDPAuthFailureMessage(ctx, d, err, authStatusBridgeGenericText)

	if message != authStatusBridgeGenericText {
		t.Fatalf("message = %q, want %q", message, authStatusBridgeGenericText)
	}

	if resolver.called {
		t.Fatal("resolver was called without a policy i18n key")
	}
}

func TestIDPAuthFailurePolicyTerminalFlag(t *testing.T) {
	err := idpservice.NewAuthFailureError(
		stderrors.New("policy rejected login"),
		idpservice.AuthFailureStatus{
			PolicyTerminal: true,
		},
	)

	if !idpAuthFailurePolicyTerminal(err) {
		t.Fatal("expected terminal policy failure")
	}

	if idpAuthFailurePolicyTerminal(stderrors.New("plain failure")) {
		t.Fatal("plain failures must not be treated as policy-terminal")
	}
}

func TestIDPAuthFailureAllowsDelayedResponseForEligiblePolicyFailure(t *testing.T) {
	err := idpservice.NewAuthFailureError(
		stderrors.New("standard password failure"),
		idpservice.AuthFailureStatus{
			PolicyTerminal:          true,
			DelayedResponseEligible: true,
		},
	)

	if !idpAuthFailureAllowsDelayedResponse(err) {
		t.Fatal("standard password failures must be deferred when delayed_response is enabled")
	}

	blocked := idpservice.NewAuthFailureError(
		stderrors.New("policy rejected login"),
		idpservice.AuthFailureStatus{
			PolicyTerminal: true,
		},
	)

	if idpAuthFailureAllowsDelayedResponse(blocked) {
		t.Fatal("policy-terminal failures must bypass delayed_response")
	}
}

func TestIDPAuthStatusBridgePersistsDelayedResponseMetadata(t *testing.T) {
	mgr := &mockCookieManager{data: map[string]any{}}
	status := idpAuthStatusBridge{
		StatusMessage:    authStatusBridgeFallback,
		I18NKey:          authStatusBridgeKey,
		ResponseLanguage: "de",
	}

	storeIDPAuthStatusBridge(mgr, status)

	loaded, ok := loadIDPAuthStatusBridge(mgr)
	if !ok {
		t.Fatal("expected stored auth status bridge")
	}

	if loaded != status {
		t.Fatalf("loaded status = %#v, want %#v", loaded, status)
	}

	clearIDPAuthStatusBridge(mgr)

	if _, ok := loadIDPAuthStatusBridge(mgr); ok {
		t.Fatal("expected auth status bridge to be cleared")
	}
}

type recordingIDPStatusResolver struct {
	selection  localization.StatusMessage
	preference localization.LanguagePreference
	resolved   localization.ResolvedStatusMessage
	failOnCall bool
	called     bool
}

func (r *recordingIDPStatusResolver) ResolveStatusMessage(
	_ context.Context,
	selection localization.StatusMessage,
	preference localization.LanguagePreference,
) localization.ResolvedStatusMessage {
	r.called = true
	r.selection = selection
	r.preference = preference

	if r.failOnCall {
		panic("resolver should not be called")
	}

	return r.resolved
}

func authStatusBridgeDeps(resolver localization.MessageResolver) *deps.Deps {
	return &deps.Deps{
		Cfg:             &mockFrontendCfg{},
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		MessageResolver: resolver,
	}
}

func authStatusBridgeContext(path string, acceptLanguage string) *gin.Context {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil)

	if acceptLanguage != "" {
		ctx.Request.Header.Set("Accept-Language", acceptLanguage)
	}

	ctx.Set(definitions.CtxGUIDKey, "auth-status-bridge-test")

	return ctx
}
