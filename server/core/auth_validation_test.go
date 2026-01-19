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
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func setupAuthDeps(t *testing.T) AuthDeps {
	db, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	return AuthDeps{
		Cfg:          config.GetFile(),
		Env:          config.NewTestEnvironmentConfig(),
		Logger:       logger,
		Redis:        redisClient,
		AccountCache: nil,
		Channel:      nil,
	}
}

func TestAuthValidation_EmptyUsername_JSON(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps(t)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	// Setup request
	body := []byte(`{"username": "", "password": "password"}`)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/json", bytes.NewBuffer(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	// Setup context variables
	ctx.Set(definitions.CtxServiceKey, definitions.ServJSON)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	// Execute
	auth := NewAuthStateWithSetupWithDeps(ctx, deps)

	// Assertions
	assert.Nil(t, auth, "NewAuthStateWithSetupWithDeps should return nil when validation fails")
	assert.True(t, ctx.IsAborted(), "Context should be aborted")
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Check JSON response
	assert.Contains(t, w.Body.String(), `"field":"Username"`)
	assert.Contains(t, w.Body.String(), `"message":"This field is required"`)
}

func TestAuthValidation_EmptyPassword_JSON(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps(t)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	// Setup request
	body := []byte(`{"username": "user1", "password": ""}`)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/json", bytes.NewBuffer(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	// Setup context variables
	ctx.Set(definitions.CtxServiceKey, definitions.ServJSON)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	// Execute
	auth := NewAuthStateWithSetupWithDeps(ctx, deps)

	// Assertions
	assert.Nil(t, auth, "NewAuthStateWithSetupWithDeps should return nil for empty password")
	assert.True(t, ctx.IsAborted(), "Context should be aborted")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), `"field":"Password"`)
	assert.Contains(t, w.Body.String(), `"message":"This field is required"`)
}

func TestAuthValidation_EmptyUsername_BasicAuth(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps(t)

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
	// because it only sets up the state. The actual extraction happens in ProcessFeatures or ProcessAuthentication.
	assert.NotNil(t, auth)

	// Now simulate the handler processing
	authState := auth.(*AuthState)
	abort := authState.ProcessFeatures(ctx)

	assert.True(t, abort)
	assert.True(t, ctx.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthValidation_EmptyCredentials_BasicAuth(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps(t)

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
	_ = authState.ProcessFeatures(ctx)

	// Check if errors were registered
	assert.Len(t, ctx.Errors, 2)
	assert.ErrorIs(t, ctx.Errors[0].Err, errors.ErrEmptyUsername)
	assert.ErrorIs(t, ctx.Errors[1].Err, errors.ErrEmptyPassword)
}

func TestAuthValidation_InvalidJSON(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps(t)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	// Setup request with invalid JSON
	body := []byte(`{"username": "user1", "password": "pass"`) // Missing closing brace
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/json", bytes.NewBuffer(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	// Setup context variables
	ctx.Set(definitions.CtxServiceKey, definitions.ServJSON)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	// Execute
	auth := NewAuthStateWithSetupWithDeps(ctx, deps)

	// Assertions
	assert.Nil(t, auth, "NewAuthStateWithSetupWithDeps should return nil for invalid JSON")
	assert.True(t, ctx.IsAborted(), "Context should be aborted")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), `"error"`)
}

func TestAuthValidation_EmptyUsername_Header(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps(t)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	// Setup request (Empty User Header)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/header", nil)
	ctx.Request.Header.Set("Auth-User", "") // Assuming default header name is Auth-User

	// Setup context variables
	ctx.Set(definitions.CtxServiceKey, definitions.ServHeader)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	// Execute
	auth := NewAuthStateWithSetupWithDeps(ctx, deps)

	// Assertions
	assert.Nil(t, auth, "NewAuthStateWithSetupWithDeps should return nil when username is empty in headers")
	assert.NotNil(t, ctx.Errors.Last(), "A Gin error should be registered")
	assert.ErrorIs(t, ctx.Errors.Last().Err, errors.ErrEmptyUsername)
}

func TestAuthValidation_EmptyUsername_SASLAuthd(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps(t)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	// Setup request (Empty username in Form)
	body := []byte("username=&password=pass")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/saslauthd", bytes.NewBuffer(body))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Setup context variables
	ctx.Set(definitions.CtxServiceKey, definitions.ServSaslauthd)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	// Execute
	auth := NewAuthStateWithSetupWithDeps(ctx, deps)

	// Assertions
	assert.Nil(t, auth, "NewAuthStateWithSetupWithDeps should return nil when username is empty in form")
	assert.NotNil(t, ctx.Errors.Last(), "A Gin error should be registered")
	assert.ErrorIs(t, ctx.Errors.Last().Err, errors.ErrEmptyUsername)
}
