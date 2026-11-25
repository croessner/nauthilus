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

package supportapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/croessner/nauthilus/v4/server/jsonstrict"
	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// errOperationPanicked marks an operation that panicked; the answer is INTERNAL_ERROR and the process keeps running.
var errOperationPanicked = errors.New("support operation panicked")

// codeInvalidRequest is the invalid-request code shared by every support service.
const codeInvalidRequest supportaccess.ErrorCode = "INVALID_REQUEST"

// errorStatus maps the stable codes of every support service to HTTP statuses. MCP reports every non-200 status as a
// tool error carrying the same envelope.
var errorStatus = map[supportaccess.ErrorCode]int{
	codeInvalidRequest:           http.StatusBadRequest,
	"WINDOW_TOO_LARGE":           http.StatusBadRequest,
	"INVALID_CURSOR":             http.StatusBadRequest,
	"INVALID_ATTEMPT_ID":         http.StatusBadRequest,
	"FORBIDDEN":                  http.StatusForbidden,
	"QUERY_TOO_BROAD":            http.StatusUnprocessableEntity,
	"HISTORY_BUSY":               http.StatusTooManyRequests,
	"OPERATIONS_BUSY":            http.StatusTooManyRequests,
	"HISTORY_NOT_CONFIGURED":     http.StatusServiceUnavailable,
	"OPERATIONS_NOT_CONFIGURED":  http.StatusServiceUnavailable,
	"HISTORY_SOURCE_UNAVAILABLE": http.StatusServiceUnavailable,
	"HISTORY_READER_UNSAFE":      http.StatusServiceUnavailable,
	"HISTORY_TIMEOUT":            http.StatusServiceUnavailable,
	"INTERNAL_ERROR":             http.StatusInternalServerError,
}

// Response is the transport-neutral outcome of one operation: an HTTP status and the exact JSON body bytes.
type Response struct {
	cause  error
	Body   []byte
	Code   supportaccess.ErrorCode
	Status int
}

// Cause returns the internal error cause for host-side logging; it never reaches a caller.
func (r Response) Cause() error {
	return r.cause
}

// IsError reports whether the response is an error envelope.
func (r Response) IsError() bool {
	return r.Status != http.StatusOK
}

// errorBody is the fixed error envelope.
type errorBody struct {
	Error         errorDetail `json:"error"`
	SchemaVersion string      `json:"schema_version"`
}

// errorDetail carries the stable code and its fixed message.
type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Execute decodes raw arguments, calls the operation with the verified credential, and renders the result or the
// stable error. Authorization stays in the service: a credential without the operation's permission gets FORBIDDEN.
func (s Services) Execute(ctx context.Context, operation Operation, credential supportaccess.VerifiedCredential, raw []byte) (response Response) {
	defer func() {
		if recovered := recover(); recovered != nil {
			response = renderError(operation.errors, operation.errors.asError(fmt.Errorf("%w: %v", errOperationPanicked, recovered)))
		}
	}()

	if operation.respond != nil {
		return operation.respond(ctx, s, credential, raw)
	}

	if operation.execute == nil {
		return InvalidRequest(operation)
	}

	result, err := operation.execute(ctx, s, credential, raw)
	if err != nil {
		return renderError(operation.errors, operation.errors.asError(err))
	}

	body, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return renderError(operation.errors, operation.errors.asError(marshalErr))
	}

	return Response{Status: http.StatusOK, Body: body}
}

// InvalidRequest renders the invalid-request envelope of an operation for transport-level rejections (oversized,
// wrong content type, query parameters).
func InvalidRequest(operation Operation) Response {
	catalog := operation.errors
	if catalog.message == nil {
		catalog = historyErrors
	}

	return renderError(catalog, catalog.invalid())
}

// renderError renders one stable error with its status.
func renderError(catalog errorCatalog, serviceErr *supportaccess.Error) Response {
	status, ok := errorStatus[serviceErr.Code]
	if !ok {
		status = http.StatusInternalServerError
	}

	body, _ := json.Marshal(errorBody{SchemaVersion: catalog.schemaVersion,
		Error: errorDetail{Code: string(serviceErr.Code), Message: catalog.message(serviceErr.Code)}})

	return Response{Status: status, Body: body, Code: serviceErr.Code, cause: errors.Unwrap(serviceErr)}
}

// DecodeStrict decodes exactly one JSON object into target: unknown fields, duplicate member names, trailing data,
// and non-object values are refused. Every transport decodes operation arguments with it.
func DecodeStrict(raw []byte, target any) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || jsonstrict.HasDuplicateNames(trimmed) {
		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return false
	}

	_, err := decoder.Token()

	return errors.Is(err, io.EOF)
}

// codeResponseTooLarge marks a result above a transport's size bound.
const codeResponseTooLarge supportaccess.ErrorCode = "RESPONSE_TOO_LARGE"

// ResponseTooLarge renders the envelope a transport returns instead of a result above its size bound.
func ResponseTooLarge(operation Operation) Response {
	catalog := operation.errors
	if catalog.message == nil {
		catalog = historyErrors
	}

	body, _ := json.Marshal(errorBody{SchemaVersion: catalog.schemaVersion, Error: errorDetail{Code: string(codeResponseTooLarge),
		Message: "The result exceeds the transport size limit; narrow the window, the filters, or the page size."}})

	return Response{Status: http.StatusUnprocessableEntity, Body: body, Code: codeResponseTooLarge}
}
