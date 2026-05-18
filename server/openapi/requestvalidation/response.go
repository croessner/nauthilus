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

package requestvalidation

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"
)

// ResponseValidation configures response-contract checks around a real HTTP
// response.
type ResponseValidation struct {
	RequiredHeaderValues map[string]string
	ExpectedMediaType    string
	RequiredHeaders      []string
	ExcludeBody          bool
}

// ValidateHTTPResponse validates response against the OpenAPI operation that
// matches req.
func (validator *Validator) ValidateHTTPResponse(
	req *http.Request,
	response *http.Response,
	validation ResponseValidation,
) error {
	if response == nil {
		return fmt.Errorf("%s OpenAPI response contract: response missing", validator.name)
	}

	defer func() {
		_ = response.Body.Close()
	}()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return validator.sanitizeResponseError(req, response.Header, nil, fmt.Errorf("read response body: %w", err))
	}

	return validator.ValidateResponse(req, response.StatusCode, response.Header, body, validation)
}

// ValidateResponse validates response metadata and body bytes against the
// matching OpenAPI operation. The status code must be documented by the
// operation; body validation can be disabled for browser or header-only flows.
func (validator *Validator) ValidateResponse(
	req *http.Request,
	statusCode int,
	header http.Header,
	body []byte,
	validation ResponseValidation,
) error {
	if req == nil {
		return fmt.Errorf("%s OpenAPI response contract: request missing", validator.name)
	}

	if err := validateRequiredHeaders(header, validation); err != nil {
		return validator.sanitizeResponseError(req, header, body, err)
	}

	if err := validateExpectedMediaType(header, validation.ExpectedMediaType); err != nil {
		return validator.sanitizeResponseError(req, header, body, err)
	}

	validationReq := validator.cloneRequestMetadataForResponse(req)

	route, pathParams, err := validator.findRoute(validationReq)
	if err != nil {
		return validator.sanitizeResponseError(req, header, body, fmt.Errorf("find operation for %s %s: %w", req.Method, req.URL.Path, err))
	}

	requestInput := &openapi3filter.RequestValidationInput{
		Request:    validationReq,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			AuthenticationFunc:  openapi3filter.NoopAuthenticationFunc,
			MultiError:          true,
			SkipSettingDefaults: true,
		},
	}

	responseInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: requestInput,
		Status:                 statusCode,
		Header:                 header.Clone(),
		Body:                   io.NopCloser(bytes.NewReader(body)),
		Options: &openapi3filter.Options{
			AuthenticationFunc:    openapi3filter.NoopAuthenticationFunc,
			ExcludeResponseBody:   validation.ExcludeBody,
			IncludeResponseStatus: true,
			MultiError:            true,
			SkipSettingDefaults:   true,
		},
	}

	if err := openapi3filter.ValidateResponse(req.Context(), responseInput); err != nil {
		return validator.sanitizeResponseError(req, header, body, err)
	}

	return nil
}

func validateRequiredHeaders(header http.Header, validation ResponseValidation) error {
	for _, name := range validation.RequiredHeaders {
		if strings.TrimSpace(header.Get(name)) == "" {
			return fmt.Errorf("response header %q missing", name)
		}
	}

	for name, expected := range validation.RequiredHeaderValues {
		if got := header.Get(name); got != expected {
			return fmt.Errorf("response header %q = %q, want %q", name, got, expected)
		}
	}

	return nil
}

func validateExpectedMediaType(header http.Header, expected string) error {
	if expected == "" {
		return nil
	}

	contentType := header.Get("Content-Type")
	if contentType == "" {
		return fmt.Errorf("response Content-Type missing, want %q", expected)
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(contentType))
	}

	if mediaType != expected {
		return fmt.Errorf("response media type = %q, want %q", mediaType, expected)
	}

	return nil
}

func (validator *Validator) cloneRequestMetadataForResponse(req *http.Request) *http.Request {
	clone := validator.cloneRequestMetadata(req)
	clone.Body = http.NoBody
	clone.ContentLength = 0
	clone.GetBody = func() (io.ReadCloser, error) {
		return http.NoBody, nil
	}

	return clone
}

func (validator *Validator) sanitizeResponseError(
	req *http.Request,
	header http.Header,
	body []byte,
	err error,
) error {
	if err == nil {
		return nil
	}

	message := err.Error()
	values := collectSensitiveValues(req)
	values = append(values, sensitiveHeaderValuesFromHeader(header)...)

	if requestMediaTypeFromHeader(header.Get("Content-Type")) == mediaTypeJSON {
		values = append(values, sensitiveJSONValues(body)...)
	}

	for _, value := range values {
		if len(value) < 4 {
			continue
		}

		message = strings.ReplaceAll(message, value, redactedValue)
	}

	message = sensitiveAssignmentPattern.ReplaceAllString(message, `${1}${2}`+redactedValue)

	return fmt.Errorf("%s OpenAPI response contract: %s", validator.name, message)
}

func requestMediaTypeFromHeader(contentType string) string {
	if contentType == "" {
		return ""
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(contentType))
	}

	return strings.ToLower(mediaType)
}
