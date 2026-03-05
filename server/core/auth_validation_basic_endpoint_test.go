//go:build auth_basic_endpoint

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

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestAuthValidation_EmptyUsername_BasicAuth(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	// Setup request (No Basic Auth header)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/basic", nil)

	// Setup context variables
	ctx.Set(definitions.CtxServiceKey, definitions.ServBasic)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	// Execute NewAuthStateWithSetupWithDeps
	auth := NewAuthStateWithSetupWithDeps(ctx, deps)

	// For Basic Auth, NewAuthStateWithSetupWithDeps doesn't fail if headers are missing,
	// because it only sets up the state. The actual extraction happens in HandleAuthentication.
	assert.NotNil(t, auth)

	// Now simulate the handler processing
	authState := auth.(*AuthState)
	authState.HandleAuthentication(ctx)

	assert.True(t, ctx.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthValidation_EmptyCredentials_BasicAuth(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	// Setup request with Basic Auth header but empty user/pass
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/basic", nil)
	ctx.Request.SetBasicAuth("", "")

	// Setup context variables
	ctx.Set(definitions.CtxServiceKey, definitions.ServBasic)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	// Execute NewAuthStateWithSetupWithDeps
	auth := NewAuthStateWithSetupWithDeps(ctx, deps)
	assert.NotNil(t, auth)

	// Now simulate the handler processing
	authState := auth.(*AuthState)
	authState.HandleAuthentication(ctx)

	// Check if errors were registered
	assert.Len(t, ctx.Errors, 2)
	assert.ErrorIs(t, ctx.Errors[0].Err, errors.ErrEmptyUsername)
	assert.ErrorIs(t, ctx.Errors[1].Err, errors.ErrEmptyPassword)
}
