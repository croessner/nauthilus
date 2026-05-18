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

// Package requesttest provides reusable OpenAPI request-contract helpers for
// handler tests.
package requesttest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/openapi/requestvalidation"
)

const (
	mediaTypeFormURLEncoded = "application/x-www-form-urlencoded"
	mediaTypeJSON           = "application/json"
)

// Validator wraps the runtime-safe OpenAPI request validator with testing
// constructors.
type Validator struct {
	*requestvalidation.Validator
}

// Case describes one request-contract validation sample.
type Case struct {
	Request                  *http.Request
	Name                     string
	WantErrorContains        string
	ForbiddenErrorSubstrings []string
	WantValid                bool
}

// NewJSONRequest builds an httptest request with an application/json body.
func NewJSONRequest(method string, target string, body string) *http.Request {
	return NewRequest(method, target, mediaTypeJSON, body)
}

// NewFormRequest builds an httptest request with a form-urlencoded body.
func NewFormRequest(method string, target string, body string) *http.Request {
	return NewRequest(method, target, mediaTypeFormURLEncoded, body)
}

// NewRequest builds an httptest request with an optional Content-Type header.
func NewRequest(method string, target string, contentType string, body string) *http.Request {
	var reader io.Reader

	if body != "" {
		reader = strings.NewReader(body)
	}

	req := httptest.NewRequest(method, target, reader)

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return req
}

// WithHeaders adds headers to req and returns the same request for table setup.
func WithHeaders(req *http.Request, values map[string]string) *http.Request {
	for name, value := range values {
		req.Header.Set(name, value)
	}

	return req
}

// NewManagementValidator loads the management OpenAPI document.
func NewManagementValidator(t testing.TB) *Validator {
	t.Helper()

	validator, err := requestvalidation.NewManagementValidator()
	if err != nil {
		t.Fatalf("load management OpenAPI validator: %v", err)
	}

	return &Validator{Validator: validator}
}

// NewIDPValidator loads the IdP OpenAPI document.
func NewIDPValidator(t testing.TB) *Validator {
	t.Helper()

	validator, err := requestvalidation.NewIDPValidator()
	if err != nil {
		t.Fatalf("load idp OpenAPI validator: %v", err)
	}

	return &Validator{Validator: validator}
}

// AssertCases validates a table of valid and invalid request samples.
func AssertCases(t *testing.T, validator *Validator, cases []Case) {
	t.Helper()

	for _, tt := range cases {
		t.Run(tt.Name, func(t *testing.T) {
			err := validator.Validate(tt.Request)

			if tt.WantValid {
				if err != nil {
					t.Fatalf("request contract validation failed: %v", err)
				}

				return
			}

			if err == nil {
				t.Fatal("request contract validation passed for an invalid request")
			}

			message := err.Error()

			if tt.WantErrorContains != "" && !strings.Contains(message, tt.WantErrorContains) {
				t.Fatalf("error = %q, want substring %q", message, tt.WantErrorContains)
			}

			for _, forbidden := range tt.ForbiddenErrorSubstrings {
				if strings.Contains(message, forbidden) {
					t.Fatalf("error = %q, must not contain sensitive value %q", message, forbidden)
				}
			}
		})
	}
}
