package core

import (
	"errors"
	"net/http"

	gin "github.com/gin-gonic/gin"
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
	}
}
