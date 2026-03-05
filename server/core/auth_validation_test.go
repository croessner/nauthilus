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

func setupAuthDeps() AuthDeps {
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

func TestAuthValidation_EmptyField_JSON(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		expectedField string
	}{
		{
			name:          "EmptyUsername",
			body:          `{"username": "", "password": "password"}`,
			expectedField: "Username",
		},
		{
			name:          "EmptyPassword",
			body:          `{"username": "user1", "password": ""}`,
			expectedField: "Password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupMinimalTestConfig(t)
			gin.SetMode(gin.TestMode)
			deps := setupAuthDeps()

			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)

			ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/json", bytes.NewBuffer([]byte(tt.body)))
			ctx.Request.Header.Set("Content-Type", "application/json")

			ctx.Set(definitions.CtxServiceKey, definitions.ServJSON)
			ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

			auth := NewAuthStateWithSetupWithDeps(ctx, deps)

			assert.Nil(t, auth, "NewAuthStateWithSetupWithDeps should return nil when validation fails")
			assert.True(t, ctx.IsAborted(), "Context should be aborted")
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), `"field":"`+tt.expectedField+`"`)
			assert.Contains(t, w.Body.String(), `"message":"This field is required"`)
		})
	}
}

func TestAuthValidation_InvalidJSON(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps()

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
	deps := setupAuthDeps()

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

func TestAuthValidation_EmptyUsername_Form(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)
	deps := setupAuthDeps()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	// Setup request (Empty username in Form)
	body := []byte("username=&password=pass")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/json", bytes.NewBuffer(body))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Setup context variables
	ctx.Set(definitions.CtxServiceKey, definitions.ServJSON)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	// Execute
	auth := NewAuthStateWithSetupWithDeps(ctx, deps)

	// Assertions
	assert.Nil(t, auth, "NewAuthStateWithSetupWithDeps should return nil when username is empty in form")
	assert.NotNil(t, ctx.Errors.Last(), "A Gin error should be registered")
	assert.ErrorIs(t, ctx.Errors.Last().Err, errors.ErrEmptyUsername)
}
