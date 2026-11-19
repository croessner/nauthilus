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

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/secret"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const (
	callerTestUnrestricted = "management"
	callerTestScoped       = "support-console"
	callerTestPassword     = "caller-test-secret-1"
	callerTestOtherSecret  = "caller-test-secret-2"
)

// callerTestConfig configures the unrestricted credential and one scoped support credential.
func callerTestConfig(enabled bool) *config.FileSettings {
	return &config.FileSettings{Server: &config.ServerSection{BasicAuth: config.BackchannelBasicAuth{
		Enabled:  enabled,
		Username: callerTestUnrestricted,
		Password: secret.New(callerTestPassword),
		Users: []config.BackchannelBasicAuthUser{{
			Username: callerTestScoped,
			Password: secret.New(callerTestOtherSecret),
			Scopes:   []string{definitions.ScopeHistoryRead, definitions.ScopeOperationsRead},
		}},
	}}}
}

// TestAuthenticateBasicCallerResolvesConfiguredCredentials verifies which caller each credential yields.
func TestAuthenticateBasicCallerResolvesConfiguredCredentials(t *testing.T) {
	tests := []struct {
		name             string
		username         string
		password         string
		disabled         bool
		wantCaller       bool
		wantUnrestricted bool
	}{
		{name: "unrestricted credential", username: callerTestUnrestricted, password: callerTestPassword, wantCaller: true, wantUnrestricted: true},
		{name: "scoped credential", username: callerTestScoped, password: callerTestOtherSecret, wantCaller: true},
		{name: "scoped username with the unrestricted password", username: callerTestScoped, password: callerTestPassword},
		{name: "unrestricted username with the scoped password", username: callerTestUnrestricted, password: callerTestOtherSecret},
		{name: "unknown username", username: "nobody", password: callerTestPassword},
		{name: "empty credentials", username: "", password: ""},
		{name: "disabled basic auth", username: callerTestScoped, password: callerTestOtherSecret, disabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller := AuthenticateBasicCaller(callerTestConfig(!tt.disabled), tt.username, tt.password)

			assert.Equal(t, tt.wantCaller, caller != nil)
			assert.Equal(t, tt.wantUnrestricted, caller.Unrestricted())

			if tt.wantCaller {
				assert.Equal(t, tt.username, caller.Identity())
				assert.Equal(t, CallerMethodBasic, caller.Method())
			}
		})
	}
}

// TestCallerScopeDecisions pins the difference between holding a scope and being granted a management route.
func TestCallerScopeDecisions(t *testing.T) {
	scoped := NewScopedCaller(CallerMethodBasic, callerTestScoped, []string{definitions.ScopeHistoryRead})
	unrestricted := NewUnrestrictedBasicCaller(callerTestUnrestricted)

	var missing *Caller

	assert.True(t, scoped.HasScope(definitions.ScopeHistoryRead))
	assert.True(t, scoped.Grants(definitions.ScopeSecurity, definitions.ScopeHistoryRead))
	assert.False(t, scoped.Grants(definitions.ScopeSecurity, definitions.ScopeAdmin))
	assert.False(t, scoped.HasAllScopes(definitions.ScopeHistoryRead, definitions.ScopeSecurity))
	assert.True(t, scoped.HasAllScopes(definitions.ScopeHistoryRead))

	// The unrestricted credential passes management routes without holding any scope.
	assert.True(t, unrestricted.Grants(definitions.ScopeSecurity))
	assert.False(t, unrestricted.HasScope(definitions.ScopeHistoryRead))
	assert.False(t, unrestricted.HasAnyScope(definitions.ScopeSecurity, definitions.ScopeHistoryRead))

	assert.False(t, missing.Grants(definitions.ScopeSecurity))
	assert.False(t, missing.HasAllScopes())
	assert.Empty(t, missing.Identity())
}

// TestStoreCallerMarksOnlyTheUnrestrictedCredential verifies that a scoped credential never sets the marker
// downstream code reads as full management access.
func TestStoreCallerMarksOnlyTheUnrestrictedCredential(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tt := range []struct {
		name   string
		caller *Caller
		marked bool
	}{
		{name: "unrestricted", caller: NewUnrestrictedBasicCaller(callerTestUnrestricted), marked: true},
		{name: "scoped", caller: NewScopedCaller(CallerMethodBasic, callerTestScoped, []string{definitions.ScopeAdmin})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			StoreCaller(ctx, tt.caller)

			assert.Same(t, tt.caller, CallerFromContext(ctx))
			assert.Equal(t, tt.marked, ctx.GetBool(definitions.CtxBasicAuthValidatedKey))
			assert.Equal(t, string(CallerMethodBasic), ctx.GetString(definitions.CtxAuthMethodKey))
		})
	}
}

// TestAuthorizeScopedBasicCaller verifies the Basic authorization of scoped routes outside the backchannel group.
func TestAuthorizeScopedBasicCaller(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Cleanup(SetCallerRejectionDelayForTest(time.Millisecond))

	tests := []struct {
		name           string
		username       string
		password       string
		noCredentials  bool
		disabled       bool
		wantPresented  bool
		wantAuthorized bool
		wantStatus     int
	}{
		{name: "scoped credential with the scope", username: callerTestScoped, password: callerTestOtherSecret, wantPresented: true, wantAuthorized: true, wantStatus: http.StatusOK},
		{name: "unrestricted credential holds no scope", username: callerTestUnrestricted, password: callerTestPassword, wantPresented: true, wantStatus: http.StatusForbidden},
		{name: "wrong password", username: callerTestScoped, password: "wrong", wantPresented: true, wantStatus: http.StatusUnauthorized},
		{name: "no basic credentials", noCredentials: true, wantStatus: http.StatusOK},
		{name: "basic auth disabled", username: callerTestScoped, password: callerTestOtherSecret, disabled: true, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/custom/report", nil)

			if !tt.noCredentials {
				ctx.Request.SetBasicAuth(tt.username, tt.password)
			}

			presented, authorized := AuthorizeScopedBasicCaller(
				ctx, callerTestConfig(!tt.disabled), []string{definitions.ScopeOperationsRead}, "insufficient permissions",
			)

			assert.Equal(t, tt.wantPresented, presented)
			assert.Equal(t, tt.wantAuthorized, authorized)
			assert.Equal(t, tt.wantStatus, recorder.Code)
			assert.Equal(t, tt.wantAuthorized, CallerFromContext(ctx) != nil)
		})
	}
}
