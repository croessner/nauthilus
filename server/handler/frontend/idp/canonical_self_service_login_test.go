// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

func TestCanonicalSelfServiceMissingSessionCompletesPasswordLoginAndOpensPortal(t *testing.T) {
	gin.SetMode(gin.TestMode)

	journey := newCanonicalSelfServiceLoginJourney(t)
	entryCookie, loginTarget := journey.enter(t)
	rotatedCookie, portalTarget := journey.authenticate(t, entryCookie, loginTarget)

	assertCanonicalSelfServiceLoginState(t, journey.runtime, entryCookie, rotatedCookie)
	journey.assertPortal(t, rotatedCookie, portalTarget)
}

type canonicalSelfServiceLoginJourney struct {
	runtime *cookie.CanonicalRuntime
	router  *gin.Engine
}

// newCanonicalSelfServiceLoginJourney composes the real handlers with bounded test doubles at backend boundaries.
func newCanonicalSelfServiceLoginJourney(t *testing.T) *canonicalSelfServiceLoginJourney {
	t.Helper()

	runtime, _, _ := seedCanonicalIDPFlow(t, nil)

	handler, err := NewCanonicalFrontendHandler(&deps.Deps{
		Cfg: &mockFrontendCfg{}, Env: config.NewTestEnvironmentConfig(),
		LangManager: &mockMultiLangManager{}, Logger: slog.Default(),
	}, runtime)
	if err != nil {
		t.Fatalf("compose canonical self-service login handler: %v", err)
	}

	handler.canonicalPasswordAuthenticator = canonicalSelfServicePasswordAuthenticator(t)
	handler.canonicalSelfServiceBackendResolver = newCanonicalSelfServiceBackendResolver(t)

	return &canonicalSelfServiceLoginJourney{
		runtime: runtime,
		router:  canonicalSelfServiceLoginRouter(t, runtime, handler),
	}
}

// enter opens the portal without a browser envelope and returns its typed internal login continuation.
func (journey *canonicalSelfServiceLoginJourney) enter(t *testing.T) (*http.Cookie, string) {
	t.Helper()

	entry := httptest.NewRecorder()
	journey.router.ServeHTTP(
		entry,
		httptest.NewRequest(http.MethodGet, definitions.MFARoot+"/register/home/de", nil),
	)

	if entry.Code != http.StatusFound {
		t.Fatalf("self-service entry status = %d, want %d", entry.Code, http.StatusFound)
	}

	loginTarget, err := url.Parse(entry.Header().Get("Location"))
	if err != nil || loginTarget.Path != "/login/de" || loginTarget.Query().Get(flowdomain.FlowTicketParameter) == "" {
		t.Fatalf("self-service login target = %q, err = %v", entry.Header().Get("Location"), err)
	}

	return canonicalResponseCookie(t, entry), entry.Header().Get("Location")
}

// authenticate submits the primary credentials and returns the rotated browser envelope and portal target.
func (journey *canonicalSelfServiceLoginJourney) authenticate(
	t *testing.T,
	entryCookie *http.Cookie,
	loginTarget string,
) (*http.Cookie, string) {
	t.Helper()

	form := url.Values{"username": {"alice"}, "password": {"correct-password"}}
	loginRequest := httptest.NewRequest(
		http.MethodPost,
		loginTarget,
		strings.NewReader(form.Encode()),
	)
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRequest.AddCookie(entryCookie)

	login := httptest.NewRecorder()
	journey.router.ServeHTTP(login, loginRequest)

	wantPortal := definitions.MFARoot + "/register/home/de"
	if login.Code != http.StatusSeeOther || login.Header().Get("Location") != wantPortal {
		t.Fatalf(
			"self-service password completion = %d %q, want %d %q",
			login.Code,
			login.Header().Get("Location"),
			http.StatusSeeOther,
			wantPortal,
		)
	}

	return canonicalResponseCookie(t, login), wantPortal
}

// assertPortal verifies the rotated session renders the protected localized 2FA management view.
func (journey *canonicalSelfServiceLoginJourney) assertPortal(
	t *testing.T,
	rotatedCookie *http.Cookie,
	wantPortal string,
) {
	t.Helper()

	portalRequest := httptest.NewRequest(http.MethodGet, wantPortal, nil)
	portalRequest.AddCookie(rotatedCookie)

	portal := httptest.NewRecorder()
	journey.router.ServeHTTP(portal, portalRequest)

	if portal.Code != http.StatusOK || !strings.Contains(portal.Body.String(), "SELF-SERVICE alice") {
		t.Fatalf("self-service portal = status %d body %q", portal.Code, portal.Body.String())
	}
}

// canonicalSelfServiceLoginRouter composes the exact entry, login, and protected portal boundaries for the journey test.
func canonicalSelfServiceLoginRouter(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	handler *FrontendHandler,
) *gin.Engine {
	t.Helper()

	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("self-service-login").Parse(`
{{ define "idp_error_modal.html" }}{{ .Message }}{{ end }}
{{ define "idp_2fa_home.html" }}SELF-SERVICE {{ .Username }}{{ end }}
`)))

	localize := func(ctx *gin.Context) {
		ctx.Set(
			definitions.CtxLocalizedKey,
			i18n.NewLocalizer((&mockMultiLangManager{}).GetBundle(), "de"),
		)
		ctx.Next()
	}
	router.GET(
		definitions.MFARoot+"/register/home/:languageTag",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalSelfServiceEntry),
		localize,
		handler.CanonicalSelfServiceLoginMiddleware(),
		handler.TwoFAHome,
	)
	router.POST(
		"/login/:languageTag",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		localize,
		handler.PostLogin,
	)

	return router
}

// canonicalSelfServicePasswordAuthenticator returns the selected test identity for the internal login flow.
func canonicalSelfServicePasswordAuthenticator(t *testing.T) canonicalPasswordAuthenticator {
	t.Helper()

	return func(
		_ *gin.Context,
		flowContext postLoginFlowContext,
		credentials postLoginCredentials,
	) (canonicalPasswordAuthentication, error) {
		if flowContext.state == nil || flowContext.state.Type != flowdomain.FlowTypeSelfServiceLogin ||
			flowContext.state.Protocol != flowdomain.FlowProtocolInternal || flowContext.protocol != definitions.ProtoIDP ||
			credentials.username != "alice" || credentials.password != "correct-password" {
			t.Fatalf("self-service authentication context = %#v credentials = %#v", flowContext, credentials)
		}

		return canonicalPasswordAuthentication{
			user: backend.NewUser("alice", "Canonical Alice", "identity-42"),
			backendRef: core.RemoteBackendRef{
				Type: "remote", Name: "canonical-remote", Protocol: definitions.ProtoIDP,
				Authority: "canonical-authority", OpaqueToken: "canonical-target-capability",
			},
		}, nil
	}
}

// newCanonicalSelfServiceBackendResolver exposes the authenticated identity to the protected portal view.
func newCanonicalSelfServiceBackendResolver(t *testing.T) canonicalSelfServiceBackendResolver {
	t.Helper()

	return func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
	) (*UserBackendData, uint8, error) {
		if identity.Account != "alice" || identity.Reference != "identity-42" || identity.Protocol != definitions.ProtoIDP {
			t.Fatalf("self-service portal identity = %#v", identity)
		}

		return &UserBackendData{
			Username: "alice", UniqueUserID: "identity-42", DisplayName: "Canonical Alice",
		}, uint8(definitions.BackendRemote), nil
	}
}

// canonicalResponseCookie returns the newest non-empty canonical envelope emitted by one response.
func canonicalResponseCookie(t *testing.T, response *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()

	var selected *http.Cookie

	for _, current := range response.Result().Cookies() {
		if current.Name == definitions.SecureDataCookieName && current.Value != "" && current.MaxAge >= 0 {
			selected = current
		}
	}

	if selected == nil {
		t.Fatalf("response has no live canonical envelope: %#v", response.Result().Cookies())
	}

	return selected
}

// assertCanonicalSelfServiceLoginState verifies rotation, identity publication, and one-shot flow consumption.
func assertCanonicalSelfServiceLoginState(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	entryCookie *http.Cookie,
	rotatedCookie *http.Cookie,
) {
	t.Helper()

	oldRequest := httptest.NewRequest(http.MethodGet, "/login/de", nil)
	oldRequest.AddCookie(entryCookie)

	if _, err := runtime.Open(context.Background(), oldRequest); err == nil {
		t.Fatal("pre-authentication canonical envelope remained valid after rotation")
	}

	newRequest := httptest.NewRequest(http.MethodGet, definitions.MFARoot+"/register/home/de", nil)
	newRequest.AddCookie(rotatedCookie)

	session, err := runtime.Open(context.Background(), newRequest)
	if err != nil {
		t.Fatalf("open authenticated self-service session: %v", err)
	}

	identity, authenticated := session.Identity()
	if !authenticated || identity.Account != "alice" || identity.Reference != "identity-42" ||
		identity.Protocol != definitions.ProtoIDP || len(session.Anchor.Value.SelfServiceFlows) != 0 {
		t.Fatalf(
			"authenticated self-service session = identity %#v authenticated %t flows %#v",
			identity,
			authenticated,
			session.Anchor.Value.SelfServiceFlows,
		)
	}
}
