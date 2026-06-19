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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

type listAccountsAcceptNegotiationCase struct {
	name              string
	accept            string
	wantStatus        int
	wantContentTypeIn []string
}

var listAccountsAcceptNegotiationCases = []listAccountsAcceptNegotiationCase{
	{
		name:              "exact-cbor",
		accept:            "application/cbor",
		wantStatus:        http.StatusOK,
		wantContentTypeIn: []string{"application/cbor"},
	},
	{
		name:              "multi-value-prefer-cbor",
		accept:            "application/cbor, application/json;q=0.5",
		wantStatus:        http.StatusOK,
		wantContentTypeIn: []string{"application/cbor"},
	},
	{
		name:              "multi-value-prefer-json",
		accept:            "application/json, application/cbor;q=0.4",
		wantStatus:        http.StatusOK,
		wantContentTypeIn: []string{"application/json; charset=utf-8"},
	},
	{
		name:              "wildcard-subtype",
		accept:            "application/*",
		wantStatus:        http.StatusOK,
		wantContentTypeIn: []string{"application/cbor", "application/json; charset=utf-8", "application/x-www-form-urlencoded"},
	},
	{
		name:              "wildcard-any",
		accept:            "*/*",
		wantStatus:        http.StatusOK,
		wantContentTypeIn: []string{"application/cbor", "application/json; charset=utf-8", "application/x-www-form-urlencoded", "text/plain", "text/plain; charset=utf-8"},
	},
	{
		name:              "missing-accept-header",
		accept:            "",
		wantStatus:        http.StatusOK,
		wantContentTypeIn: []string{"application/cbor", "application/json; charset=utf-8", "application/x-www-form-urlencoded", "text/plain", "text/plain; charset=utf-8"},
	},
	{
		name:              "case-insensitive",
		accept:            "Application/CBOR",
		wantStatus:        http.StatusOK,
		wantContentTypeIn: []string{"application/cbor"},
	},
	{
		name:              "with-parameters",
		accept:            "application/json; charset=utf-8",
		wantStatus:        http.StatusOK,
		wantContentTypeIn: []string{"application/json; charset=utf-8"},
	},
	{
		name:              "q-zero-excludes",
		accept:            "application/cbor;q=0, application/json",
		wantStatus:        http.StatusOK,
		wantContentTypeIn: []string{"application/json; charset=utf-8"},
	},
	{
		name:              "no-acceptable-type",
		accept:            "image/png",
		wantStatus:        http.StatusUnsupportedMediaType,
		wantContentTypeIn: nil,
	},
}

// TestHandleAuthentication_ListAccounts_AcceptNegotiation reproduces the
// content-negotiation behaviour expected for list-accounts responses. It
// covers single values, multi-value Accept headers with quality values,
// wildcards, and the empty-header default case.
func TestHandleAuthentication_ListAccounts_AcceptNegotiation(t *testing.T) {
	for _, tt := range listAccountsAcceptNegotiationCases {
		t.Run(tt.name, func(t *testing.T) {
			assertListAccountsAcceptNegotiation(t, tt)
		})
	}
}

func assertListAccountsAcceptNegotiation(t *testing.T, tt listAccountsAcceptNegotiationCase) {
	t.Helper()

	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)

	deps := setupAuthDeps()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/cbor?mode=list-accounts", nil)

	if tt.accept != "" {
		ctx.Request.Header.Set("Accept", tt.accept)
	}

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			ListAccounts: true,
			Protocol:     new(config.Protocol),
			Service:      definitions.ServCBOR,
		},
	}

	auth.HandleAuthentication(ctx)

	assert.Equal(t, tt.wantStatus, w.Code)

	if tt.wantStatus == http.StatusOK {
		got := w.Header().Get("Content-Type")
		assert.Contains(t, tt.wantContentTypeIn, got, "Content-Type %q not in expected set", got)
	}
}
