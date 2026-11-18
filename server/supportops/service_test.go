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

package supportops

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

var testNow = time.Date(2026, time.November, 18, 8, 0, 0, 0, time.UTC)

// fakeSource returns a fixed result and records the queries it received.
type fakeSource struct {
	result  SourceResult
	name    string
	kind    SourceKind
	block   bool
	mu      sync.Mutex
	queries []Query
}

// Name returns the configured name.
func (f *fakeSource) Name() string { return f.name }

// Kind returns the configured kind.
func (f *fakeSource) Kind() SourceKind { return f.kind }

// Collect records the query and answers the fixed result, or waits for cancellation when block is set.
func (f *fakeSource) Collect(ctx context.Context, query Query) SourceResult {
	f.mu.Lock()
	f.queries = append(f.queries, query)
	f.mu.Unlock()

	if f.block {
		<-ctx.Done()
	}

	return f.result
}

// auditLog collects audit entries.
type auditLog struct {
	mu      sync.Mutex
	entries []supportaccess.AuditEntry
}

// RecordSupportAudit stores one entry.
func (a *auditLog) RecordSupportAudit(_ context.Context, entry supportaccess.AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.entries = append(a.entries, entry)
}

// operator returns a caller with the operations scope.
func operator() Caller {
	return NewCaller(supportaccess.VerifiedCredential{Method: supportaccess.CredentialOAuthUser, ClientID: "cli", Subject: "anna",
		Scopes: []string{definitions.ScopeOperationsRead}})
}

// runtimeFinding returns a current-state LDAP finding.
func runtimeFinding(status Status, symptoms ...Symptom) Finding {
	return Finding{Component: ComponentLDAP, Source: SourceRuntime, Status: status, Symptoms: symptoms,
		Scope: FindingScope{Kind: ScopeInstance, Instance: "mx-1"}, Freshness: Freshness{Basis: BasisCurrentState, ObservedAt: testNow},
		Labels: map[string]string{"pool": "auth", "target": "ldap://dc1\u202e"}}
}

// newTestService builds a service over the given sources at a fixed time.
func newTestService(t *testing.T, audit *auditLog, sources ...Source) *Service {
	t.Helper()

	service, err := NewService(Options{Sources: sources, Instance: "mx-1", Deployment: "prod", Audit: audit,
		Now: func() time.Time { return testNow }, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	return service
}

// TestDiagnoseAuthorizationAndValidation pins authorize-before-validate, the fixed vocabularies, and the window bounds.
func TestDiagnoseAuthorizationAndValidation(t *testing.T) {
	audit := &auditLog{}
	runtime := &fakeSource{name: SourceRuntime, kind: SourceKindLocalCurrent, result: SourceResult{Report: SourceReport{Status: SourceStatusOK}}}
	service := newTestService(t, audit, runtime)

	historyOnly := NewCaller(supportaccess.VerifiedCredential{Method: supportaccess.CredentialOIDCBearer, ClientID: "console",
		Scopes: []string{definitions.ScopeHistoryRead}})

	for name, tc := range map[string]struct {
		caller  Caller
		request DiagnosticsRequest
		code    ErrorCode
	}{
		"missing scope":        {historyOnly, DiagnosticsRequest{SchemaVersion: "x"}, CodeForbidden},
		"zero caller":          {Caller{}, DiagnosticsRequest{SchemaVersion: SchemaVersion}, CodeForbidden},
		"bad schema":           {operator(), DiagnosticsRequest{SchemaVersion: "2"}, CodeInvalidRequest},
		"unknown component":    {operator(), DiagnosticsRequest{SchemaVersion: SchemaVersion, Components: []string{"shell"}}, CodeInvalidRequest},
		"repeated source":      {operator(), DiagnosticsRequest{SchemaVersion: SchemaVersion, Sources: []string{SourceLoki, SourceLoki}}, CodeInvalidRequest},
		"bad audit reference":  {operator(), DiagnosticsRequest{SchemaVersion: SchemaVersion, AuditReference: "a b"}, CodeInvalidRequest},
		"inverted window":      {operator(), DiagnosticsRequest{SchemaVersion: SchemaVersion, Window: &Window{From: testNow, Until: testNow.Add(-time.Minute)}}, CodeInvalidRequest},
		"future window":        {operator(), DiagnosticsRequest{SchemaVersion: SchemaVersion, Window: &Window{From: testNow, Until: testNow.Add(time.Hour)}}, CodeInvalidRequest},
		"window above maximum": {operator(), DiagnosticsRequest{SchemaVersion: SchemaVersion, Window: &Window{From: testNow.Add(-25 * time.Hour), Until: testNow}}, CodeWindowTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := service.Diagnose(context.Background(), tc.caller, tc.request)
			if got := AsError(err); got.Code != tc.code || got.Message() != ErrorMessage(tc.code) {
				t.Fatalf("Diagnose() = %v, want %s", err, tc.code)
			}
		})
	}

	if len(runtime.queries) != 0 {
		t.Fatal("a rejected call must not reach a source")
	}

	assertDeniedAudit(t, audit, 9, 2)

	var nilService *Service

	if _, err := nilService.Diagnose(context.Background(), operator(), DiagnosticsRequest{}); AsError(err).Code != CodeNotConfigured {
		t.Fatalf("nil service = %v", err)
	}

	if _, err := nilService.Diagnose(context.Background(), Caller{}, DiagnosticsRequest{}); AsError(err).Code != CodeForbidden {
		t.Fatalf("nil service without permission = %v", err)
	}
}

// assertDeniedAudit checks that every call was audited and that denied calls are not marked allowed.
func assertDeniedAudit(t *testing.T, audit *auditLog, calls int, deniedCalls int) {
	t.Helper()

	denied := 0

	for _, entry := range audit.entries {
		if entry.Service != auditService || entry.Operation != operationDiagnose {
			t.Fatalf("audit entry = %+v", entry)
		}

		if entry.ResultCode == string(CodeForbidden) {
			denied++

			if entry.Allowed {
				t.Fatalf("a denied call must be audited as not allowed: %+v", entry)
			}
		}
	}

	if len(audit.entries) != calls || denied != deniedCalls {
		t.Fatalf("audit = %+v", audit.entries)
	}
}

// TestDiagnoseAssemblesSeparateFindingsAndHypotheses pins deterministic ids, label sanitizing, the separation of
// findings and hypotheses, the source reports, and the notes.
func TestDiagnoseAssemblesSeparateFindingsAndHypotheses(t *testing.T) {
	audit := &auditLog{}
	runtime := &fakeSource{name: SourceRuntime, kind: SourceKindLocalCurrent, result: SourceResult{
		Report: SourceReport{Status: SourceStatusOK, Coverage: Coverage{Instances: []string{"mx-1"}, View: CoverageLocalInstance}},
		Findings: []Finding{
			{Component: ComponentRedis, Source: SourceRuntime, Status: StatusNotObserved, Freshness: Freshness{Basis: BasisProcessLifetimeCounter}},
			runtimeFinding(StatusFailing, Symptom{Code: SymptomLDAPTargetUnhealthy, Count: 1}),
		}}}
	loki := &fakeSource{name: SourceLoki, kind: SourceKindHistorical, result: SourceResult{
		Report: SourceReport{Status: SourceStatusPartial, Truncated: true},
		Findings: []Finding{{Component: ComponentLDAP, Source: SourceLoki, Status: StatusObserved,
			Scope: FindingScope{Kind: ScopeInstance, Instance: "mx-1"}, Freshness: Freshness{Basis: BasisLogWindow},
			Symptoms: []Symptom{{Code: SymptomLDAPConnectionError, Count: 5}}}}}}
	service := newTestService(t, audit, runtime, loki)

	result, err := service.Diagnose(context.Background(), operator(), DiagnosticsRequest{SchemaVersion: SchemaVersion,
		Components: []string{ComponentRedis, ComponentLDAP}, AuditReference: "INC-42"})
	if err != nil {
		t.Fatalf("Diagnose() = %v", err)
	}

	assertAssembledFindings(t, result)
	assertAssembledHypotheses(t, result)
	assertAssembledNotes(t, result)
	assertAssembledQueryAndAudit(t, runtime, audit)
}

// assertAssembledFindings checks the deterministic order, ids, and label sanitizing.
func assertAssembledFindings(t *testing.T, result *DiagnosticsResult) {
	t.Helper()

	ids := []string{result.Findings[0].ID, result.Findings[1].ID, result.Findings[2].ID}
	if !slices.Equal(ids, []string{"F1", "F2", "F3"}) || result.Findings[0].Component != ComponentLDAP ||
		result.Findings[0].Source != SourceRuntime || result.Findings[1].Source != SourceLoki ||
		result.Findings[2].Component != ComponentRedis {
		t.Fatalf("findings = %+v", result.Findings)
	}

	if target := result.Findings[0].Labels["target"]; target != "ldap://dc1\uFFFD" {
		t.Fatalf("label = %q, want a sanitized value", target)
	}

	if result.Sources[0].Name != SourceRuntime || result.Sources[1].Name != SourceLoki || result.Sources[1].Kind != SourceKindHistorical {
		t.Fatalf("sources = %+v", result.Sources)
	}
}

// assertAssembledHypotheses checks the one medium-confidence hypothesis over both sources.
func assertAssembledHypotheses(t *testing.T, result *DiagnosticsResult) {
	t.Helper()

	if len(result.Hypotheses) != 1 || result.Hypotheses[0].Code != HypothesisDirectoryUnreachable ||
		result.Hypotheses[0].Confidence != ConfidenceMedium || !slices.Equal(result.Hypotheses[0].FindingIDs, []string{"F1", "F2"}) {
		t.Fatalf("hypotheses = %+v", result.Hypotheses)
	}
}

// assertAssembledNotes checks the reading notes of a runtime plus partial Loki answer.
func assertAssembledNotes(t *testing.T, result *DiagnosticsResult) {
	t.Helper()

	for _, note := range []string{NoteValuesAreUntrusted, NoteLocalViewNotCluster, NoteRuntimeCountersAreLifetime,
		NoteHistoricalSourceIncomplete, NoteHypothesesAreNotFindings} {
		if !slices.Contains(result.Notes, note) {
			t.Fatalf("notes = %v, missing %s", result.Notes, note)
		}
	}
}

// assertAssembledQueryAndAudit checks the query the source received and the audit entry.
func assertAssembledQueryAndAudit(t *testing.T, runtime *fakeSource, audit *auditLog) {
	t.Helper()

	query := runtime.queries[0]
	if !slices.Equal(query.Components, []string{ComponentLDAP, ComponentRedis}) || !query.Window.Until.Equal(testNow) ||
		!query.Window.From.Equal(testNow.Add(-DefaultWindow)) || query.Instance != "mx-1" {
		t.Fatalf("query = %+v", query)
	}

	if len(audit.entries) != 1 || !audit.entries[0].Allowed || audit.entries[0].Results != 3 ||
		audit.entries[0].AuditReference != "INC-42" || audit.entries[0].CallerIdentity != "cli#anna" {
		t.Fatalf("audit = %+v", audit.entries)
	}
}

// TestDiagnoseSourceSelectionAndTimeout pins not_requested and not_configured reports, the past-window note, and a
// source that runs out of time.
func TestDiagnoseSourceSelectionAndTimeout(t *testing.T) {
	slow := &fakeSource{name: SourceRuntime, kind: SourceKindLocalCurrent, block: true, result: SourceResult{Report: SourceReport{Status: SourceStatusOK}}}

	service, err := NewService(Options{Sources: []Source{slow}, Now: func() time.Time { return testNow }, Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	past := &Window{From: testNow.Add(-3 * time.Hour), Until: testNow.Add(-2 * time.Hour)}

	result, err := service.Diagnose(context.Background(), operator(), DiagnosticsRequest{SchemaVersion: SchemaVersion, Window: past})
	if err != nil {
		t.Fatal(err)
	}

	if result.Sources[0].Status != SourceStatusTimeout || result.Sources[1].Status != SourceStatusNotConfigured {
		t.Fatalf("sources = %+v", result.Sources)
	}

	if !slices.Contains(result.Notes, NoteRuntimeIsCurrentStateOnly) || !slices.Contains(result.Notes, NoteNoHistoricalSource) {
		t.Fatalf("notes = %v", result.Notes)
	}

	result, err = service.Diagnose(context.Background(), operator(), DiagnosticsRequest{SchemaVersion: SchemaVersion, Sources: []string{SourceLoki}})
	if err != nil {
		t.Fatal(err)
	}

	if result.Sources[0].Status != SourceStatusNotRequested || len(result.Findings) != 0 {
		t.Fatalf("sources = %+v", result.Sources)
	}
}

// TestNewServiceRejectsUnknownSources pins the constructor boundary.
func TestNewServiceRejectsUnknownSources(t *testing.T) {
	if _, err := NewService(Options{}); err == nil {
		t.Fatal("a service without sources must be rejected")
	}

	if _, err := NewService(Options{Sources: []Source{&fakeSource{name: "shell"}}}); err == nil {
		t.Fatal("an unknown source must be rejected")
	}
}

// TestHypothesisConfidenceNeverExceedsMedium pins the confidence and caveat rules.
func TestHypothesisConfidenceNeverExceedsMedium(t *testing.T) {
	counterOnly := deriveHypotheses([]Finding{{ID: "F1", Source: SourceRuntime, Status: StatusObserved,
		Freshness: Freshness{Basis: BasisProcessLifetimeCounter}, Symptoms: []Symptom{{Code: SymptomRedisPoolTimeouts, Count: 3}}}})

	if len(counterOnly) != 1 || counterOnly[0].Confidence != ConfidenceLow ||
		!slices.Contains(counterOnly[0].Caveats, CaveatCounterNotWindowBound) || !slices.Contains(counterOnly[0].Caveats, CaveatSingleSourceEvidence) {
		t.Fatalf("hypotheses = %+v", counterOnly)
	}

	if quiet := deriveHypotheses([]Finding{{ID: "F1", Status: StatusNotObserved, Symptoms: []Symptom{{Code: SymptomRedisPoolTimeouts}}}}); len(quiet) != 0 {
		t.Fatalf("a not_observed finding must not raise a hypothesis: %+v", quiet)
	}
}

// TestErrorSharing pins that diagnostics errors use the shared support error type.
func TestErrorSharing(t *testing.T) {
	err := newError(CodeBusy, errors.New("internal"))

	var shared *supportaccess.Error
	if !errors.As(error(err), &shared) || shared.Code != CodeBusy || shared.Error() != ErrorMessage(CodeBusy) {
		t.Fatalf("error = %v", err)
	}

	if AsError(errors.New("boom")).Code != CodeInternal {
		t.Fatal("unknown errors must map to INTERNAL_ERROR")
	}
}
