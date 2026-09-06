package idp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	identityprovider "github.com/croessner/nauthilus/v3/server/idp"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// TestMFABudgetIdentityFromAccountAttribute covers legacy LDAP sessions without a cached account name.
func TestMFABudgetIdentityFromAccountAttribute(t *testing.T) {
	for _, stableID := range []string{"", "factor-stable-id"} {
		t.Run("stable-id="+stableID, func(t *testing.T) {
			auth := &core.AuthState{}
			auth.Runtime.AccountField = "uid"
			auth.SetAttributeValues("uid", []any{"canonical-factor"})

			identity, err := mfaBackendBudgetIdentity(&UserBackendData{AuthState: auth, UniqueUserID: stableID})

			want := stableID
			if want == "" {
				want = "canonical-factor"
			}

			if err != nil || identity != want {
				t.Fatalf("identity = %q, error = %v; want %q", identity, err, want)
			}
		})
	}
}

// configureMFAAttemptTestStorage supplies isolated real script semantics for browser verification tests.
func configureMFAAttemptTestStorage(t *testing.T, handler *FrontendHandler) {
	t.Helper()
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})

	t.Cleanup(func() { _ = client.Close() })

	if handler.deps == nil {
		handler.deps = &deps.Deps{Cfg: &mockFrontendCfg{}}
	}

	handler.deps.Redis = rediscli.NewTestClient(client)
}

// budgetMFAProvider observes verifier dispatch through both browser code handlers.
type budgetMFAProvider struct {
	identityprovider.MFAProvider
	calls int
}

// VerifyTOTP records a rejected TOTP attempt.
func (p *budgetMFAProvider) VerifyTOTP(*gin.Context, string, string, uint8) (bool, error) {
	p.calls++
	return false, nil
}

// UseRecoveryCode records a rejected recovery attempt.
func (p *budgetMFAProvider) UseRecoveryCode(*gin.Context, string, string, uint8) (bool, error) {
	p.calls++
	return false, nil
}

// TestBrowserCodeBudgetBindsFactorIdentity preserves one budget across methods, target accounts and new sessions.
func TestBrowserCodeBudgetBindsFactorIdentity(t *testing.T) {
	h := NewFrontendHandler(newLoginMFAViewHandler().deps)
	configureMFAAttemptTestStorage(t, h)

	provider := &budgetMFAProvider{}
	h.mfa = provider
	router := gin.New()
	router.SetHTMLTemplate(loginMFATestTemplate())
	router.Use(func(ctx *gin.Context) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyUsername:              ctx.Query("target"),
			definitions.SessionKeyMFAFactorAccount:      "master",
			definitions.SessionKeyMFAFactorUniqueUserID: "master-id",
			definitions.SessionKeyUniqueUserID:          ctx.Query("target"),
		}}
		cookie.SetAuthResult(mgr, ctx.Query("target"), definitions.AuthResultOK)
		ctx.Set(definitions.CtxSecureDataKey, mgr)
		ctx.Set(definitions.CtxLocalizedKey, i18n.NewLocalizer((&mockLangManager{}).GetBundle(), "en"))
		ctx.Next()
	})
	router.POST("/login/totp", h.PostLoginTOTP)
	router.POST("/login/recovery", h.PostLoginRecovery)

	for attempt := range 11 {
		route := "/login/totp"
		if attempt%2 == 0 {
			route = "/login/recovery"
		}

		request := httptest.NewRequest(http.MethodPost, fmt.Sprintf("%s?target=user-%d", route, attempt), strings.NewReader("code=invalid"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		want := http.StatusOK
		if attempt == 10 {
			want = http.StatusTooManyRequests
		}

		if response.Code != want {
			t.Fatalf("attempt %d status %d, want %d", attempt+1, response.Code, want)
		}
	}

	if provider.calls != 10 {
		t.Fatalf("verifier calls %d, want 10", provider.calls)
	}
}
