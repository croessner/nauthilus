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

package requesttest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/openapi/requestvalidation"
)

// ResponseValidation configures response-contract checks around a real
// httptest response.
type ResponseValidation = requestvalidation.ResponseValidation

// AssertRecorderResponse validates recorder against the OpenAPI operation that
// matches req.
func AssertRecorderResponse(
	t testing.TB,
	validator *Validator,
	req *http.Request,
	recorder *httptest.ResponseRecorder,
	validation ResponseValidation,
) {
	t.Helper()

	if err := validator.ValidateRecorderResponse(req, recorder, validation); err != nil {
		t.Fatalf("response contract validation failed: %v", err)
	}
}

// ValidateRecorderResponse validates a httptest recorder response against the
// matching OpenAPI operation.
func (validator *Validator) ValidateRecorderResponse(
	req *http.Request,
	recorder *httptest.ResponseRecorder,
	validation ResponseValidation,
) error {
	if validator == nil || validator.Validator == nil {
		return fmt.Errorf("OpenAPI response contract: validator missing")
	}

	if recorder == nil {
		return fmt.Errorf("OpenAPI response contract: recorder missing")
	}

	return validator.ValidateHTTPResponse(req, recorder.Result(), validation)
}
