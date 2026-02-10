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

package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSetOperationMode_ListAccountsSetsProtocol(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps(t)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/?mode=list-accounts", nil)
	ctx.Set(definitions.CtxGUIDKey, "test-guid")

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			Protocol: new(config.Protocol),
		},
	}

	auth.SetOperationMode(ctx)

	assert.True(t, auth.Request.ListAccounts)
	assert.Equal(t, definitions.ProtoAccountProvider, auth.Request.Protocol.Get())
}
