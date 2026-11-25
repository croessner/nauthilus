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
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/openapi/requesttest"
	"github.com/croessner/nauthilus/v4/server/supportops"
)

const logOverviewTarget = "/api/v1/support/operations/log-overview"

// fixedLogSource is a Loki source that answers one fixed log overview.
type fixedLogSource struct {
	result supportops.LogOverviewSourceResult
}

// Name returns the Loki source name.
func (fixedLogSource) Name() string { return supportops.SourceLoki }

// Kind returns the historical kind.
func (fixedLogSource) Kind() supportops.SourceKind { return supportops.SourceKindHistorical }

// Collect answers an empty diagnostics contribution.
func (fixedLogSource) Collect(context.Context, supportops.Query) supportops.SourceResult {
	return supportops.SourceResult{Report: supportops.SourceReport{Status: supportops.SourceStatusOK}}
}

// LogOverview answers the fixed overview.
func (f fixedLogSource) LogOverview(context.Context, supportops.LogOverviewQuery) supportops.LogOverviewSourceResult {
	return f.result
}

// logOverviewService builds a service whose Loki source counted one RBL failure with resolver addresses.
func logOverviewService(t *testing.T) *supportops.Service {
	t.Helper()

	bucket := supportops.Window{From: fixtureBase.Add(-15 * time.Minute), Until: fixtureBase}
	source := fixedLogSource{result: supportops.LogOverviewSourceResult{Buckets: []supportops.Window{bucket},
		Report: supportops.SourceReport{Status: supportops.SourceStatusOK, Coverage: supportops.Coverage{Instances: []string{"mx-1"},
			View: supportops.CoverageLogLabels, From: supportops.TimePointer(bucket.From), Until: supportops.TimePointer(bucket.Until)}},
		Series: []supportops.LogSeries{{Instance: "mx-1", Level: supportops.LogLevelError, Counts: []int64{4},
			Message: "lookup 9.113.0.203.zen.example on 192.0.2.53:53: i/o timeout"}}}}

	service, err := supportops.NewService(supportops.Options{Sources: []supportops.Source{source}, Instance: "mx-1",
		Now: func() time.Time { return fixtureBase }})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return service
}

// TestSupportLogOverviewScopeAndContract pins the operations scope gate and the response contract of the log overview,
// and that a resolver address never leaves the host.
func TestSupportLogOverviewScopeAndContract(t *testing.T) {
	validator := requesttest.NewManagementValidator(t)
	deps := &handlerdeps.Deps{SupportOperations: logOverviewService(t)}
	body := `{"schema_version":"1","window":{"from":"2026-01-01T00:00:00Z","until":"2026-01-01T00:15:00Z"}}`

	for name, tc := range map[string]struct {
		body   string
		code   string
		scopes []string
		status int
	}{
		"operations scope":   {`{"schema_version":"1"}`, "", []string{definitions.ScopeOperationsRead}, http.StatusOK},
		"history scope only": {`{"schema_version":"1"}`, "FORBIDDEN", []string{definitions.ScopeHistoryDetail}, http.StatusForbidden},
		"unknown level":      {`{"schema_version":"1","levels":["debug"]}`, "INVALID_REQUEST", []string{definitions.ScopeOperationsRead}, http.StatusBadRequest},
		"explicit window":    {body, "", []string{definitions.ScopeOperationsRead}, http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			request, recorder := serve(testRouterWithDeps(t, deps, bearer(tc.scopes...), false), logOverviewTarget, tc.body)
			if recorder.Code != tc.status {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), tc.status)
			}

			if tc.code != "" && errorCode(t, recorder) != tc.code {
				t.Fatalf("body = %s, want %s", recorder.Body.String(), tc.code)
			}

			if tc.status == http.StatusOK && !strings.Contains(recorder.Body.String(), `"message":"lookup \u003cvalue\u003e on \u003cvalue\u003e: i/o timeout"`) &&
				!strings.Contains(recorder.Body.String(), `"message":"lookup <value> on <value>: i/o timeout"`) {
				t.Fatalf("body = %s, want the normalized RBL group", recorder.Body.String())
			}

			if strings.Contains(recorder.Body.String(), "192.0.2.53") {
				t.Fatalf("a resolver address left the host: %s", recorder.Body.String())
			}

			requesttest.AssertRecorderResponse(t, validator, request, recorder, requesttest.ResponseValidation{
				RequiredHeaderValues: map[string]string{"Cache-Control": "no-store"}})
		})
	}
}
