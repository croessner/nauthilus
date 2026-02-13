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
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// JSONErrorMsg represents an error message in JSON format with the field name and error message string.
type JSONErrorMsg struct {
	// Field represents the name of the field that caused the validation error.
	Field string `json:"field"`

	// Message represents the error message associated with the validation error.
	Message string `json:"message"`
}

// getErrorMsg returns a user-friendly error message based on the validation error received.
func getErrorMsg(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "This field is required"
	case "ip":
		return "This field must be a valid IP address"
	}

	return "Unknown error"
}

// HandleJSONError handles JSON validation errors by aborting the request and returning a JSON response with error details.
func HandleJSONError(ctx *gin.Context, err error) {
	var validationErrors validator.ValidationErrors

	if errors.As(err, &validationErrors) {
		errorMsgList := make([]JSONErrorMsg, len(validationErrors))

		for i, validationError := range validationErrors {
			errorMsgList[i] = JSONErrorMsg{validationError.Field(), getErrorMsg(validationError)}
		}

		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": errorMsgList})

		return
	}

	ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
}

// HandleJSONValidationError handles manual validation errors by returning a JSON response in the same format as Gin's validation errors.
func HandleJSONValidationError(ctx *gin.Context, field, message string) {
	ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
		"errors": []JSONErrorMsg{
			{Field: field, Message: message},
		},
	})
}
