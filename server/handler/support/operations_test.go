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

package support

import (
	"net/http"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/openapi/requesttest"
	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/runtimesource"
	"github.com/prometheus/client_golang/prometheus"
)

const diagnosticsTarget = "/api/v1/support/operations/diagnostics"

// operationsService builds a diagnostics service over a registry with one unhealthy LDAP target.
func operationsService(t *testing.T) *supportops.Service {
	t.Helper()

	registry := prometheus.NewRegistry()
	health := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "ldap_target_health"}, []string{"pool", "target"})
	registry.MustRegister(health)
	health.WithLabelValues("auth", "ldap://dc1.example.test").Set(0)

	service, err := supportops.NewService(supportops.Options{Sources: []supportops.Source{runtimesource.New(registry)},
		Instance: "mx-1", Now: func() time.Time { return fixtureBase }})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return service
}

// TestSupportOperationsScopeAndContract pins the operations scope gate, the 503 without a service, and the response
// contract of processed and rejected calls.
func TestSupportOperationsScopeAndContract(t *testing.T) {
	validator := requesttest.NewManagementValidator(t)
	service := operationsService(t)
	body := `{"schema_version":"1","components":["ldap","redis"],"audit_reference":"INC-7"}`

	for name, tc := range map[string]struct {
		deps   *handlerdeps.Deps
		body   string
		code   string
		scopes []string
		status int
	}{
		"operations scope":     {&handlerdeps.Deps{SupportOperations: service}, body, "", []string{definitions.ScopeOperationsRead}, http.StatusOK},
		"history scope only":   {&handlerdeps.Deps{SupportOperations: service}, body, "FORBIDDEN", []string{definitions.ScopeHistoryDetail}, http.StatusForbidden},
		"not configured":       {&handlerdeps.Deps{}, body, "OPERATIONS_NOT_CONFIGURED", []string{definitions.ScopeOperationsRead}, http.StatusServiceUnavailable},
		"unknown component":    {&handlerdeps.Deps{SupportOperations: service}, `{"schema_version":"1","components":["shell"]}`, "INVALID_REQUEST", []string{definitions.ScopeOperationsRead}, http.StatusBadRequest},
		"unknown field":        {&handlerdeps.Deps{SupportOperations: service}, `{"schema_version":"1","query":"x"}`, "INVALID_REQUEST", []string{definitions.ScopeOperationsRead}, http.StatusBadRequest},
		"window above maximum": {&handlerdeps.Deps{SupportOperations: service}, `{"schema_version":"1","window":{"from":"2026-01-01T00:00:00Z","until":"2026-01-03T00:00:00Z"}}`, "WINDOW_TOO_LARGE", []string{definitions.ScopeOperationsRead}, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			request, recorder := serve(testRouterWithDeps(t, tc.deps, bearer(tc.scopes...), false), diagnosticsTarget, tc.body)
			if recorder.Code != tc.status {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), tc.status)
			}

			if tc.code != "" && errorCode(t, recorder) != tc.code {
				t.Fatalf("body = %s, want %s", recorder.Body.String(), tc.code)
			}

			requesttest.AssertRecorderResponse(t, validator, request, recorder, requesttest.ResponseValidation{
				RequiredHeaderValues: map[string]string{"Cache-Control": "no-store"}})
		})
	}
}
