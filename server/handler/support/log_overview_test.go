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

const (
	logOverviewTarget = "/api/v1/support/operations/log-overview"
	logEventsTarget   = "/api/v1/support/operations/log-events"

	// rblFailure is the complete message the fixture source logged.
	rblFailure = "lookup 9.113.0.203.zen.example on 192.0.2.53:53: i/o timeout"
)

// fixedLogSource is a Loki source that answers one fixed log overview and one fixed page of log events.
type fixedLogSource struct {
	result supportops.LogOverviewSourceResult
	events supportops.LogEventsSourceResult
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

// LogEvents answers the fixed events.
func (f fixedLogSource) LogEvents(context.Context, supportops.LogEventsQuery) supportops.LogEventsSourceResult {
	return f.events
}

// logOverviewService builds a service whose Loki source counted one RBL failure with resolver addresses and stored
// its line with a password field.
func logOverviewService(t *testing.T) *supportops.Service {
	t.Helper()

	bucket := supportops.Window{From: fixtureBase.Add(-15 * time.Minute), Until: fixtureBase}
	source := fixedLogSource{result: supportops.LogOverviewSourceResult{Buckets: []supportops.Window{bucket},
		Report: supportops.SourceReport{Status: supportops.SourceStatusOK, Coverage: supportops.Coverage{Instances: []string{"mx-1"},
			View: supportops.CoverageLogLabels, From: supportops.TimePointer(bucket.From), Until: supportops.TimePointer(bucket.Until)}},
		Series: []supportops.LogSeries{{Instance: "mx-1", Level: supportops.LogLevelError, Counts: []int64{4},
			Message: rblFailure}}},
		events: supportops.LogEventsSourceResult{LimitApplied: 100, Report: source0Report(),
			Lines: []supportops.LogLine{{At: fixtureBase.Add(-time.Minute), Instance: "mx-1", Labels: map[string]string{"pod": "mx-1"},
				Line: `{"level":"ERROR","msg":"RBL check failed","error":"` + rblFailure + `","username":"alice","password":"hunter2"}`}}}}

	service, err := supportops.NewService(supportops.Options{Sources: []supportops.Source{source}, Instance: "mx-1",
		Now: func() time.Time { return fixtureBase }})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return service
}

// source0Report is a complete source report of the fixture instance.
func source0Report() supportops.SourceReport {
	return supportops.SourceReport{Status: supportops.SourceStatusOK, Coverage: supportops.Coverage{Instances: []string{"mx-1"},
		View: supportops.CoverageLogLabels}}
}

// TestSupportLogOverviewScopeAndContract pins the operations scope gate and the response contract of the log overview,
// and that the logged message leaves complete.
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
		"unknown level":      {`{"schema_version":"1","levels":["trace"]}`, "INVALID_REQUEST", []string{definitions.ScopeOperationsRead}, http.StatusBadRequest},
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

			if tc.status == http.StatusOK && !strings.Contains(recorder.Body.String(), `"message":"`+rblFailure+`"`) {
				t.Fatalf("body = %s, want the complete RBL message", recorder.Body.String())
			}

			requesttest.AssertRecorderResponse(t, validator, request, recorder, requesttest.ResponseValidation{
				RequiredHeaderValues: map[string]string{"Cache-Control": "no-store"}})
		})
	}
}

// TestSupportLogEventsScopeAndContract pins the operations scope gate and the response contract of the log events:
// the stored line leaves complete with its identity and error text, and only the password is replaced.
func TestSupportLogEventsScopeAndContract(t *testing.T) {
	validator := requesttest.NewManagementValidator(t)
	deps := &handlerdeps.Deps{SupportOperations: logOverviewService(t)}

	for name, tc := range map[string]struct {
		body   string
		code   string
		scopes []string
		status int
	}{
		"operations scope":   {`{"schema_version":"1","instance":"mx-1","message":"RBL check failed"}`, "", []string{definitions.ScopeOperationsRead}, http.StatusOK},
		"history scope only": {`{"schema_version":"1"}`, "FORBIDDEN", []string{definitions.ScopeHistoryDetail}, http.StatusForbidden},
		"bad cursor":         {`{"schema_version":"1","page":{"cursor":"x"}}`, "INVALID_CURSOR", []string{definitions.ScopeOperationsRead}, http.StatusBadRequest},
		"unknown field":      {`{"schema_version":"1","query":"{}"}`, "INVALID_REQUEST", []string{definitions.ScopeOperationsRead}, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			request, recorder := serve(testRouterWithDeps(t, deps, bearer(tc.scopes...), false), logEventsTarget, tc.body)
			if recorder.Code != tc.status {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), tc.status)
			}

			if tc.code != "" && errorCode(t, recorder) != tc.code {
				t.Fatalf("body = %s, want %s", recorder.Body.String(), tc.code)
			}

			body := recorder.Body.String()
			if tc.status == http.StatusOK && (!strings.Contains(body, rblFailure) || !strings.Contains(body, `"username":"alice"`) ||
				strings.Contains(body, "hunter2") || !strings.Contains(body, `"redacted_fields":["password"]`)) {
				t.Fatalf("body = %s", body)
			}

			requesttest.AssertRecorderResponse(t, validator, request, recorder, requesttest.ResponseValidation{
				RequiredHeaderValues: map[string]string{"Cache-Control": "no-store"}})
		})
	}
}
