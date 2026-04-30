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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/encoding/cborcodec"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandleAuthentication_ListAccounts_AcceptCBOR(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)

	deps := setupAuthDeps()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/cbor?mode=list-accounts", nil)
	ctx.Request.Header.Set("Accept", "application/cbor")

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			ListAccounts: true,
			Protocol:     new(config.Protocol),
			Service:      definitions.ServCBOR,
		},
	}

	auth.HandleAuthentication(ctx)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/cbor", w.Header().Get("Content-Type"))

	var got []string
	assert.NoError(t, cborcodec.Unmarshal(w.Body.Bytes(), &got))
	assert.Empty(t, got, "no backends configured for accounts; expected empty list")
}
