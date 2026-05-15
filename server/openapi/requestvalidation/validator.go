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

// Package requestvalidation provides OpenAPI request validation for selected
// HTTP boundaries.
package requestvalidation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/croessner/nauthilus/server/openapi"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
)

const (
	mediaTypeFormURLEncoded = "application/x-www-form-urlencoded"
	mediaTypeJSON           = "application/json"
	redactedValue           = "[REDACTED]"
)

var sensitiveAssignmentPattern = regexp.MustCompile(`(?i)\b(authorization|auth-pass|password|pass|secret|assertion|client_secret|client_assertion|refresh_token|access_token|id_token|device_code|code_verifier)(\s*[:=]\s*)([^"',\s\]}]+)`)

// Validator validates HTTP requests against one loaded OpenAPI document.
type Validator struct {
	doc     *openapi3.T
	baseURL *url.URL
	name    string
}

// NewManagementValidator loads the management OpenAPI document.
func NewManagementValidator() (*Validator, error) {
	return NewValidator("management", openapi.ManagementYAML())
}

// NewIDPValidator loads the IdP OpenAPI document.
func NewIDPValidator() (*Validator, error) {
	return NewValidator("idp", openapi.IDPYAML())
}

// NewValidator loads and validates an OpenAPI document from content.
func NewValidator(name string, content []byte) (*Validator, error) {
	ctx := context.Background()
	loader := openapi3.NewLoader()
	loader.Context = ctx
	loader.IsExternalRefsAllowed = false

	doc, err := loader.LoadFromData(content)
	if err != nil {
		return nil, fmt.Errorf("parse %s OpenAPI document: %w", name, err)
	}

	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("validate %s OpenAPI document: %w", name, err)
	}

	baseURL, err := defaultServerURL(doc)
	if err != nil {
		return nil, fmt.Errorf("resolve %s OpenAPI default server: %w", name, err)
	}

	return &Validator{
		doc:     doc,
		baseURL: baseURL,
		name:    name,
	}, nil
}

// Validate checks req against the matching OpenAPI operation.
func (validator *Validator) Validate(req *http.Request) error {
	if req == nil {
		return fmt.Errorf("%s OpenAPI request contract: request missing", validator.name)
	}

	validationReq, err := validator.cloneRequestForValidation(req)
	if err != nil {
		return validator.sanitizeError(req, fmt.Errorf("prepare request: %w", err))
	}

	route, pathParams, err := validator.findRoute(validationReq)
	if err != nil {
		return validator.sanitizeError(req, fmt.Errorf("find operation for %s %s: %w", req.Method, req.URL.Path, err))
	}

	input := &openapi3filter.RequestValidationInput{
		Request:    validationReq,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			AuthenticationFunc:  openapi3filter.NoopAuthenticationFunc,
			MultiError:          true,
			SkipSettingDefaults: true,
		},
	}

	if validationReq.ContentLength > 0 && route.Operation.RequestBody == nil {
		return validator.sanitizeError(req, fmt.Errorf("request body not allowed by operation %s", route.Operation.OperationID))
	}

	if err := openapi3filter.ValidateRequest(req.Context(), input); err != nil {
		return validator.sanitizeError(req, err)
	}

	return nil
}

// OperationID resolves the OpenAPI operation id for req. Requests that do not
// match the document return matched=false and a nil error.
func (validator *Validator) OperationID(req *http.Request) (operationID string, matched bool, err error) {
	if req == nil {
		return "", false, fmt.Errorf("%s OpenAPI request contract: request missing", validator.name)
	}

	validationReq := validator.cloneRequestMetadata(req)

	route, _, err := validator.findRoute(validationReq)
	if err != nil {
		if errors.Is(err, routers.ErrPathNotFound) || errors.Is(err, routers.ErrMethodNotAllowed) {
			return "", false, nil
		}

		return "", false, err
	}

	if route.Operation == nil || route.Operation.OperationID == "" {
		return "", false, nil
	}

	return route.Operation.OperationID, true, nil
}

func (validator *Validator) findRoute(req *http.Request) (*routers.Route, map[string]string, error) {
	methodAllowed := false

	for _, path := range validator.doc.Paths.InMatchingOrder() {
		pathParams, ok := matchOpenAPIPath(path, req.URL.Path)
		if !ok {
			continue
		}

		pathItem := validator.doc.Paths.Value(path)
		if pathItem == nil {
			continue
		}

		operation := pathItem.GetOperation(req.Method)
		if operation == nil {
			methodAllowed = true

			continue
		}

		return &routers.Route{
			Spec:      validator.doc,
			Path:      path,
			PathItem:  pathItem,
			Method:    req.Method,
			Operation: operation,
		}, pathParams, nil
	}

	if methodAllowed {
		return nil, nil, routers.ErrMethodNotAllowed
	}

	return nil, nil, routers.ErrPathNotFound
}

func matchOpenAPIPath(template string, path string) (map[string]string, bool) {
	templateParts := splitOpenAPIPath(template)
	pathParts := splitOpenAPIPath(path)

	if len(templateParts) != len(pathParts) {
		return nil, false
	}

	params := make(map[string]string)

	for index, templatePart := range templateParts {
		if name, ok := openAPIPathParameterName(templatePart); ok {
			if pathParts[index] == "" {
				return nil, false
			}

			params[name] = pathParts[index]

			continue
		}

		if templatePart != pathParts[index] {
			return nil, false
		}
	}

	return params, true
}

func splitOpenAPIPath(path string) []string {
	trimmed := strings.Trim(path, "/")

	if trimmed == "" {
		return nil
	}

	return strings.Split(trimmed, "/")
}

func openAPIPathParameterName(part string) (string, bool) {
	if !strings.HasPrefix(part, "{") || !strings.HasSuffix(part, "}") {
		return "", false
	}

	name := strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
	if name == "" {
		return "", false
	}

	return name, true
}

func defaultServerURL(doc *openapi3.T) (*url.URL, error) {
	if len(doc.Servers) == 0 {
		return &url.URL{}, nil
	}

	serverURL := doc.Servers[0].URL

	for name, variable := range doc.Servers[0].Variables {
		if variable == nil {
			continue
		}

		serverURL = strings.ReplaceAll(serverURL, "{"+name+"}", variable.Default)
	}

	if serverURL == "" {
		return &url.URL{}, nil
	}

	parsed, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}

	return parsed, nil
}

func (validator *Validator) cloneRequestForValidation(req *http.Request) (*http.Request, error) {
	body, err := readAndRestoreBody(req)
	if err != nil {
		return nil, err
	}

	clone := validator.cloneRequestMetadata(req)

	if len(body) > 0 {
		clone.ContentLength = int64(len(body))
		clone.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		clone.Body, _ = clone.GetBody()
	} else {
		clone.Body = http.NoBody
		clone.GetBody = func() (io.ReadCloser, error) {
			return http.NoBody, nil
		}
		clone.ContentLength = 0
	}

	return clone, nil
}

func (validator *Validator) cloneRequestMetadata(req *http.Request) *http.Request {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.URL = cloneURL(req.URL)
	clone.Host = req.Host

	validator.applyDefaultServer(clone)

	return clone
}

func (validator *Validator) applyDefaultServer(req *http.Request) {
	if validator.baseURL == nil || validator.baseURL.Host == "" {
		return
	}

	req.URL.Scheme = validator.baseURL.Scheme
	req.URL.Host = validator.baseURL.Host
	req.Host = validator.baseURL.Host
}

func cloneURL(original *url.URL) *url.URL {
	if original == nil {
		return &url.URL{}
	}

	clone := *original

	return &clone
}

func readAndRestoreBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	return body, nil
}

func (validator *Validator) sanitizeError(req *http.Request, err error) error {
	if err == nil {
		return nil
	}

	message := err.Error()

	for _, value := range collectSensitiveValues(req) {
		if len(value) < 4 {
			continue
		}

		message = strings.ReplaceAll(message, value, redactedValue)
	}

	message = sensitiveAssignmentPattern.ReplaceAllString(message, `${1}${2}`+redactedValue)

	return fmt.Errorf("%s OpenAPI request contract: %s", validator.name, message)
}

func collectSensitiveValues(req *http.Request) []string {
	if req == nil {
		return nil
	}

	values := make([]string, 0)
	values = append(values, sensitiveHeaderValues(req)...)
	values = append(values, sensitiveQueryValues(req)...)
	values = append(values, sensitiveCookieValues(req)...)
	values = append(values, sensitiveBodyValues(req)...)

	return values
}

func sensitiveHeaderValues(req *http.Request) []string {
	return sensitiveHeaderValuesFromHeader(req.Header)
}

func sensitiveHeaderValuesFromHeader(header http.Header) []string {
	values := make([]string, 0)

	for name, headerValues := range header {
		if !isSensitiveName(name) {
			continue
		}

		values = append(values, headerValues...)
	}

	return values
}

func sensitiveQueryValues(req *http.Request) []string {
	query := req.URL.Query()
	values := make([]string, 0)

	for name, queryValues := range query {
		if !isSensitiveName(name) {
			continue
		}

		values = append(values, queryValues...)
	}

	return values
}

func sensitiveCookieValues(req *http.Request) []string {
	values := make([]string, 0)

	for _, cookie := range req.Cookies() {
		if !isSensitiveName(cookie.Name) {
			continue
		}

		values = append(values, cookie.Value)
	}

	return values
}

func sensitiveBodyValues(req *http.Request) []string {
	body, err := readAndRestoreBody(req)
	if err != nil || len(body) == 0 {
		return nil
	}

	mediaType := requestMediaType(req)

	switch mediaType {
	case mediaTypeJSON:
		return sensitiveJSONValues(body)
	case mediaTypeFormURLEncoded:
		return sensitiveFormValues(body)
	default:
		return nil
	}
}

func requestMediaType(req *http.Request) string {
	contentType := req.Header.Get("Content-Type")

	if contentType == "" {
		return ""
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(contentType))
	}

	return strings.ToLower(mediaType)
}

func sensitiveJSONValues(body []byte) []string {
	var value any

	if err := json.Unmarshal(body, &value); err != nil {
		return nil
	}

	values := make([]string, 0)
	collectSensitiveJSONValue(&values, "", value)

	return values
}

func collectSensitiveJSONValue(values *[]string, key string, value any) {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, childValue := range typed {
			collectSensitiveJSONValue(values, childKey, childValue)
		}
	case []any:
		for _, childValue := range typed {
			collectSensitiveJSONValue(values, key, childValue)
		}
	case string:
		if isSensitiveName(key) {
			*values = append(*values, typed)
		}
	}
}

func sensitiveFormValues(body []byte) []string {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil
	}

	values := make([]string, 0)

	for name, formValues := range form {
		if !isSensitiveName(name) {
			continue
		}

		values = append(values, formValues...)
	}

	return values
}

func isSensitiveName(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	normalized = strings.ReplaceAll(normalized, "_", "-")

	for _, fragment := range sensitiveNameFragments() {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}

	return false
}

func sensitiveNameFragments() []string {
	return []string{
		"authorization",
		"auth-pass",
		"password",
		"pass",
		"secret",
		"token",
		"assertion",
		"device-code",
		"code-verifier",
		"samlresponse",
	}
}
