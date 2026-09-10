// Copyright 2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/model/mfa"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

// TestSelfServiceWebAuthnRegistrationStartsEnrollment reproduces the direct portal registration conflict.
func TestSelfServiceWebAuthnRegistrationStartsEnrollment(t *testing.T) {
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)
	now := session.EvaluationTime()
	assert.NoError(t, session.CommitAssurance(context.Background(), cookie.SessionAssurance{
		Level: 1, Method: definitions.MFAMethodTOTP, Scope: canonicalSelfServiceAssuranceScope,
		ProvenAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}))
	handler := newLoginMFAViewHandler(t)
	router := canonicalWebAuthnEnrollmentRouter(runtime, handler)

	response := getCanonicalEnrollmentRequest(router, browserCookie, "/mfa/webauthn/register")
	if !assert.Equal(t, http.StatusSeeOther, response.Code) {
		return
	}

	assert.Contains(t, response.Header().Get("Location"), "/mfa/webauthn/register?flow=")
	page := getCanonicalEnrollmentRequest(router, browserCookie, response.Header().Get("Location"))
	assert.Equal(t, http.StatusOK, page.Code)

	location, err := url.Parse(response.Header().Get("Location"))
	assert.NoError(t, err)

	enrollment := sessionstate.Handle(location.Query().Get("flow"))
	ceremony := sessionstate.Handle("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	calls := 0
	handler.canonicalWebAuthnEnrollmentFinish = func(_ *gin.Context, selection canonicalEnrollmentSelectionState, got sessionstate.Handle) error {
		calls++

		assert.Nil(t, selection.parent)
		assert.True(t, selection.enrollment.Value.SelfService)
		assert.Equal(t, ceremony, got)

		return nil
	}
	finish := postCanonicalWebAuthnEnrollment(router, browserCookie, enrollment, ceremony)
	assert.Equal(t, http.StatusOK, finish.Code)
	assert.Contains(t, finish.Body.String(), "/mfa/webauthn/devices")

	replay := postCanonicalWebAuthnEnrollment(router, browserCookie, enrollment, ceremony)
	assert.Equal(t, http.StatusConflict, replay.Code)
	assert.Equal(t, 1, calls)
}

// TestWebAuthnDeleteInvalidatesCachedDuplicates prevents a stale duplicate list after deletion.
func TestWebAuthnDeleteInvalidatesCachedDuplicates(t *testing.T) {
	handler, _ := newMFASelfServiceTestHandler()
	db, mockRedis := redismock.NewClientMock()
	handler.deps.Redis = rediscli.NewTestClient(db)
	handler.deps.AccountCache = accountcache.NewManager(handler.deps.Cfg)
	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/mfa/webauthn/device/a", nil)
	ctx.Request.Header.Set("HX-Request", "true")
	auth := core.NewAuthStateFromContextWithDeps(ctx, handler.deps.Auth()).(*core.AuthState)
	mockRedis.ExpectDel(webAuthnRedisUserKey(handler.deps.Cfg, "identity-42")).SetVal(1)

	user := &backend.User{ID: "identity-42", Credentials: make([]mfa.PersistentCredential, 2)}
	handler.finishLocalWebAuthnDeviceDelete(ctx, &UserBackendData{UniqueUserID: user.ID, WebAuthnUser: user, AuthState: auth})
	assert.NoError(t, mockRedis.ExpectationsWereMet())
	assert.Equal(t, http.StatusOK, writer.Code)
	assert.Equal(t, "/mfa/webauthn/devices", writer.Header().Get("HX-Redirect"))
}
