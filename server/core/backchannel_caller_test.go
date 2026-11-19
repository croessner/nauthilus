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

package core

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	mdauth "github.com/croessner/nauthilus/v4/server/middleware/auth"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// TestBindBackchannelCallerCarriesTheTransportCaller verifies that the synthetic auth request sees the caller of
// the transport, so the list-accounts scope applies to Bearer tokens and scoped Basic credentials alike.
func TestBindBackchannelCallerCarriesTheTransportCaller(t *testing.T) {
	gin.SetMode(gin.TestMode)

	scopedBasic := func(scopes ...string) context.Context {
		return ContextWithBackchannelCaller(context.Background(),
			mdauth.NewScopedCaller(mdauth.CallerMethodBasic, "mail-frontend", scopes))
	}
	bearer := func(scope string) context.Context {
		return ContextWithOIDCClaims(context.Background(), jwt.MapClaims{"client_id": "mail-frontend", "scope": scope})
	}

	tests := []struct {
		name       string
		parent     context.Context
		wantGrant  bool
		wantClaims bool
	}{
		{name: "no caller authentication is not restricted", parent: context.Background(), wantGrant: true},
		{name: "unrestricted basic credential", wantGrant: true, parent: ContextWithBackchannelCaller(
			context.Background(), mdauth.NewUnrestrictedBasicCaller("management"))},
		{name: "scoped basic credential with the scope", parent: scopedBasic(definitions.ScopeAuthenticate, definitions.ScopeListAccounts), wantGrant: true},
		{name: "scoped basic credential without the scope", parent: scopedBasic(definitions.ScopeAuthenticate)},
		{name: "bearer claims with the scope", parent: bearer(definitions.ScopeListAccounts), wantGrant: true, wantClaims: true},
		{name: "bearer claims without the scope", parent: bearer(definitions.ScopeAuthenticate), wantClaims: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
			bindBackchannelCaller(tt.parent, ginCtx)

			if got := backchannelCallerGrants(ginCtx, definitions.ScopeListAccounts); got != tt.wantGrant {
				t.Fatalf("backchannelCallerGrants() = %t, want %t", got, tt.wantGrant)
			}

			if _, exists := ginCtx.Get(definitions.CtxOIDCClaimsKey); exists != tt.wantClaims {
				t.Fatalf("claims bound = %t, want %t", exists, tt.wantClaims)
			}

			if ginCtx.GetBool(definitions.CtxBasicAuthValidatedKey) {
				t.Fatal("the synthetic request must not carry the unrestricted Basic marker")
			}
		})
	}
}
