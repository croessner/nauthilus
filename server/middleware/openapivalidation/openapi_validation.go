// Copyright (C) 2026 Christian Roessner
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

// Package openapivalidation contains the opt-in runtime request validation
// pilot for selected OpenAPI operations.
package openapivalidation

import (
	"log/slog"
	"net/http"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/openapi/requestvalidation"
	"github.com/gin-gonic/gin"
)

const validationFailureResponse = "request contract validation failed"

// RequestValidator is the narrow validator dependency needed by the Gin
// boundary.
type RequestValidator interface {
	OperationID(req *http.Request) (operationID string, matched bool, err error)
	Validate(req *http.Request) error
}

// Config wires dependencies for the runtime validation middleware.
type Config struct {
	Validator  RequestValidator
	Logger     *slog.Logger
	Operations []string
}

// NewManagementMiddleware creates the management OpenAPI runtime validation
// middleware when the feature is explicitly enabled.
func NewManagementMiddleware(settings *config.OpenAPIValidation, logger *slog.Logger) (gin.HandlerFunc, error) {
	if settings == nil || !settings.IsEnabled() {
		return nil, nil
	}

	validator, err := requestvalidation.NewManagementValidator()
	if err != nil {
		return nil, err
	}

	return New(Config{
		Validator:  validator,
		Logger:     logger,
		Operations: settings.GetOperations(),
	}), nil
}

// New creates a Gin middleware that enforces OpenAPI request validation only
// for explicitly selected operation IDs.
func New(cfg Config) gin.HandlerFunc {
	selected := operationSet(cfg.Operations)
	logger := cfg.Logger
	validator := cfg.Validator

	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx *gin.Context) {
		if validator == nil || len(selected) == 0 {
			ctx.Next()

			return
		}

		operationID, matched, err := validator.OperationID(ctx.Request)
		if err != nil {
			logValidationFailure(ctx, logger, "", err)
			abortValidationFailure(ctx)

			return
		}

		if !matched || !selectedOperation(selected, operationID) {
			ctx.Next()

			return
		}

		if err := validator.Validate(ctx.Request); err != nil {
			logValidationFailure(ctx, logger, operationID, err)
			abortValidationFailure(ctx)

			return
		}

		ctx.Next()
	}
}

func operationSet(operations []string) map[string]struct{} {
	selected := make(map[string]struct{}, len(operations))

	for _, operation := range operations {
		selected[operation] = struct{}{}
	}

	return selected
}

func selectedOperation(selected map[string]struct{}, operationID string) bool {
	_, ok := selected[operationID]

	return ok
}

func logValidationFailure(ctx *gin.Context, logger *slog.Logger, operationID string, err error) {
	logger.Warn(
		"OpenAPI runtime request validation failed",
		definitions.LogKeyMethod, ctx.Request.Method,
		definitions.LogKeyUriPath, ctx.Request.URL.Path,
		"operation_id", operationID,
		definitions.LogKeyError, err.Error(),
	)
}

func abortValidationFailure(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
		"error": validationFailureResponse,
	})
}
