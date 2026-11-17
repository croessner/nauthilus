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

package supporthistory_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/historytest"
)

const scenarioFixture = "testdata/attempt_scenarios.json"

// scenarioBase is the instant the newest fixture row is shifted to.
var scenarioBase = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

// fixtureStore loads the scenario fixture.
func fixtureStore(t *testing.T) *historytest.Store {
	t.Helper()

	store, err := historytest.LoadFixture(scenarioFixture, scenarioBase)
	if err != nil {
		t.Fatalf("LoadFixture() error = %v", err)
	}

	return store
}

// newService builds a service over a store without an identity resolver.
func newService(t *testing.T, store supporthistory.AttemptStore) *supporthistory.Service {
	t.Helper()

	service, err := supporthistory.NewService(supporthistory.Options{Attempts: store,
		Now: func() time.Time { return scenarioBase.Add(time.Hour) }})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return service
}

// caller returns a verified bearer caller with scopes.
func caller(scopes ...string) supporthistory.Caller {
	return supporthistory.NewCaller(supporthistory.VerifiedCredential{Method: supporthistory.CredentialOIDCBearer,
		ClientID: "support-console", Scopes: scopes})
}

// searchRequest returns a search for the fixture subject over the whole fixture window.
func searchRequest() supporthistory.AttemptSearchRequest {
	return supporthistory.AttemptSearchRequest{SchemaVersion: "1",
		Subject: supporthistory.Subject{Login: "anna@example.test"},
		Filter: supporthistory.AttemptSearchFilter{From: scenarioBase.Add(-2 * time.Hour),
			Until: scenarioBase.Add(time.Minute)},
		Page: supporthistory.PageRequest{Limit: supporthistory.MaxAttemptPageLimit}}
}

// attemptsByID searches and indexes the attempts.
func attemptsByID(t *testing.T, service *supporthistory.Service, who supporthistory.Caller) (map[string]supporthistory.Attempt, *supporthistory.AttemptSearchResult) {
	t.Helper()

	result, err := service.SearchAttempts(context.Background(), who, searchRequest())
	if err != nil {
		t.Fatalf("SearchAttempts() error = %v", err)
	}

	byID := map[string]supporthistory.Attempt{}
	for _, attempt := range result.Attempts {
		byID[attempt.AttemptID] = attempt
	}

	return byID, result
}

// eventCodes lists the codes of an attempt's events.
func eventCodes(attempt supporthistory.Attempt) []string {
	codes := make([]string, 0, len(attempt.Events))
	for _, event := range attempt.Events {
		codes = append(codes, event.Code)
	}

	return codes
}

// findingCodes lists the codes of an attempt's findings.
func findingCodes(attempt supporthistory.Attempt) []string {
	codes := make([]string, 0, len(attempt.Findings))
	for _, finding := range attempt.Findings {
		codes = append(codes, finding.Code)
	}

	return codes
}

// TestSearchInterpretsEveryRecordedPath pins the evaluation matrix for the support projection.
func TestSearchInterpretsEveryRecordedPath(t *testing.T) {
	attempts, result := attemptsByID(t, newService(t, fixtureStore(t)), caller(definitions.ScopeHistoryRead))
	flow := func(digit string) string { return "fl1." + strings.Repeat(digit, 32) }

	cases := []struct {
		id, outcome, basis, progress string
		final                        bool
		codes, findings              []string
	}{
		{"rq1.req-cred", "rejected", "request_terminal_answer", "primary_rejected", true,
			[]string{supporthistory.CodeCredentialsRejected}, []string{supporthistory.CodeCredentialsRejected}},
		{"rq1.req-backend", "technical_error", "request_terminal_answer", "technical_error", true,
			[]string{supporthistory.CodeTechnicalBackend}, []string{supporthistory.CodeTechnicalBackend}},
		{"rq1.req-brute", "rejected", "request_terminal_answer", "pre_credential_rejected", true,
			[]string{supporthistory.CodeBruteForceRejected}, []string{supporthistory.CodeBruteForceRejected}},
		{"rq1.req-legacy", "unknown", "legacy", "none", false,
			[]string{supporthistory.CodeLegacyUninterpreted}, []string{}},
		{"rq1.req-unknown", "unknown", "request_terminal_answer", "none", false,
			[]string{supporthistory.CodeOutcomeNotRecorded}, []string{supporthistory.CodeOutcomeNotRecorded}},
		{flow("1"), "not_observed", "none", "second_factor_completed", false,
			[]string{supporthistory.CodePrimarySucceeded, supporthistory.CodeCredentialsRejected,
				supporthistory.CodeFactorRejected, supporthistory.CodeFactorAccepted},
			[]string{supporthistory.CodeCredentialsRejected, supporthistory.CodeFactorRejected}},
		{flow("2"), "rejected", "primary_failure_latched", "primary_failure_latched", true,
			[]string{supporthistory.CodeCredentialsRejected},
			[]string{supporthistory.CodeCredentialsRejected, supporthistory.CodeFactorOnLatchedFlow}},
		{flow("3"), "not_observed", "none", "primary_succeeded", false,
			[]string{supporthistory.CodePrimarySucceeded, supporthistory.CodeFactorRejected,
				supporthistory.CodeFactorChallengeMissing, supporthistory.CodeStepUpExpired},
			[]string{supporthistory.CodeFactorRejected, supporthistory.CodeFactorChallengeMissing, supporthistory.CodeStepUpExpired}},
		{flow("4"), "not_observed", "none", "primary_rejected", false,
			[]string{supporthistory.CodeCredentialsRejected}, []string{supporthistory.CodeCredentialsRejected}},
		{flow("5"), "not_observed", "none", "none", false,
			[]string{supporthistory.CodeFactorTechnical}, []string{supporthistory.CodeFactorTechnical}},
		{"rq1.ss-1", "not_observed", "none", "second_factor_completed", false,
			[]string{supporthistory.CodeFactorAccepted}, []string{}},
	}

	for _, want := range cases {
		t.Run(want.id, func(t *testing.T) {
			assertAttempt(t, attempts, want.id, want.outcome, want.basis, want.progress, want.final, want.codes, want.findings)
		})
	}

	if _, leaked := attempts["rq1.req-bob"]; leaked || len(attempts) != 12 {
		t.Fatalf("attempts = %v, want the subject's 12 attempts only", keys(attempts))
	}

	if result.ResultBasis != "matches_found" || result.History.Availability != "available" {
		t.Fatalf("basis/history = %s/%+v", result.ResultBasis, result.History)
	}
}

// assertAttempt compares one attempt with the expected interpretation.
func assertAttempt(t *testing.T, attempts map[string]supporthistory.Attempt, id, outcome, basis, progress string, final bool, codes, findings []string) {
	t.Helper()

	attempt, ok := attempts[id]
	if !ok {
		t.Fatalf("attempt missing; got %v", keys(attempts))
	}

	if attempt.Outcome != outcome || attempt.OutcomeBasis != basis || attempt.Progress != progress ||
		attempt.FinalOutcomeObserved != final {
		t.Fatalf("attempt = %s/%s/%s/%t, want %s/%s/%s/%t", attempt.Outcome, attempt.OutcomeBasis, attempt.Progress,
			attempt.FinalOutcomeObserved, outcome, basis, progress, final)
	}

	if got := eventCodes(attempt); !slices.Equal(got, codes) {
		t.Fatalf("event codes = %v, want %v", got, codes)
	}

	if got := findingCodes(attempt); !slices.Equal(got, findings) {
		t.Fatalf("finding codes = %v, want %v", got, findings)
	}
}

// keys lists the attempt ids.
func keys(attempts map[string]supporthistory.Attempt) []string {
	ids := make([]string, 0, len(attempts))
	for id := range attempts {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	return ids
}

// TestSearchKeepsRecordingLimitsVisible pins replay merging, conflicting rows, uncertainty, and missing rows.
func TestSearchKeepsRecordingLimitsVisible(t *testing.T) {
	attempts, _ := attemptsByID(t, newService(t, fixtureStore(t)), caller(definitions.ScopeHistoryRead))

	if got := attempts["rq1.req-cred"].Recording.ReplayedRowsMerged; got != 1 {
		t.Fatalf("replayed rows merged = %d, want 1", got)
	}

	conflict := attempts["rq1.req-conflict"]
	if conflict.Outcome != "unknown" || !slices.Contains(conflict.Recording.KnownGaps, "CONFLICTING_TERMINAL_RECORDS") {
		t.Fatalf("conflict attempt = %+v, want unknown with a gap", conflict)
	}

	if !slices.Contains(attempts["fl1."+strings.Repeat("5", 32)].Recording.KnownGaps, "PRIMARY_ROW_NOT_RECORDED") {
		t.Fatal("flow without login row must report PRIMARY_ROW_NOT_RECORDED")
	}

	if got := attempts["rq1.ss-1"].Recording.ReplayedRowsMerged; got != 1 {
		t.Fatalf("self-service replay merged = %d, want 1", got)
	}

	for _, finding := range attempts["fl1."+strings.Repeat("3", 32)].Findings {
		if finding.Code == supporthistory.CodeFactorRejected &&
			(finding.Certainty != "uncertain" || !slices.Contains(finding.Uncertainty, "WEBAUTHN_HELPER_FAILURES_REPORTED_AS_REJECTED")) {
			t.Fatalf("webauthn finding = %+v, want the helper uncertainty", finding)
		}
	}
}

// TestSupportProjectionWithholdsLatchedFactorResults pins that support sees the rejection, never the factor result.
func TestSupportProjectionWithholdsLatchedFactorResults(t *testing.T) {
	support, _ := attemptsByID(t, newService(t, fixtureStore(t)), caller(definitions.ScopeHistoryRead))
	detail, _ := attemptsByID(t, newService(t, fixtureStore(t)), caller(definitions.ScopeHistoryDetail))
	latched := "fl1." + strings.Repeat("2", 32)

	raw, _ := json.Marshal(support[latched])
	for _, forbidden := range []string{"rate_limited", "primary_failure_kept", "verified", "e-f2-"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("support projection leaks %q: %s", forbidden, raw)
		}
	}

	if support[latched].Steps.SecondFactor != "withheld" || support[latched].StartedAt != support[latched].LastObservedAt {
		t.Fatalf("support latched attempt = %+v, want withheld factor step and visible-only span", support[latched])
	}

	kept := detail[latched]
	if kept.OutcomeBasis != "primary_failure_kept" || len(kept.Events) != 4 || kept.Projection != "detail" {
		t.Fatalf("detail latched attempt = %+v, want kept failure and all events", kept)
	}

	for _, event := range kept.Events {
		if event.Stage == "primary_authentication" && event.Result == "succeeded" {
			t.Fatal("a verified factor on a latched flow must never become a primary success")
		}
	}
}

// TestSupportProjectionRedactsOtherIdentitiesInAFlow pins that another login typed in the same flow is redacted.
func TestSupportProjectionRedactsOtherIdentitiesInAFlow(t *testing.T) {
	support, _ := attemptsByID(t, newService(t, fixtureStore(t)), caller(definitions.ScopeHistoryRead))
	detail, _ := attemptsByID(t, newService(t, fixtureStore(t)), caller(definitions.ScopeHistoryDetail))
	id := "fl1." + strings.Repeat("1", 32)

	other := support[id].Events[1]
	if !other.Identity.Redacted || other.Identity.SuppliedLogin != nil || other.Identity.SubjectMatch {
		t.Fatalf("support event = %+v, want redacted foreign identity", other.Identity)
	}

	if login := detail[id].Events[1].Identity.SuppliedLogin; login == nil || *login != "mallory@example.test" {
		t.Fatalf("detail event identity = %+v, want released foreign login", detail[id].Events[1].Identity)
	}
}

// TestPagingNeverRepeatsOrSkipsAttempts walks one-attempt pages over the fixture.
func TestPagingNeverRepeatsOrSkipsAttempts(t *testing.T) {
	service := newService(t, fixtureStore(t))
	request := searchRequest()
	request.Page.Limit = 1
	seen := map[string]bool{}

	for page := 0; page < 30; page++ {
		result, err := service.SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), request)
		if err != nil {
			t.Fatalf("page %d error = %v", page, err)
		}

		for _, attempt := range result.Attempts {
			if seen[attempt.AttemptID] {
				t.Fatalf("attempt %s repeated", attempt.AttemptID)
			}

			seen[attempt.AttemptID] = true
		}

		if result.Page.NextCursor == nil {
			break
		}

		request.Page.Cursor = *result.Page.NextCursor
	}

	if len(seen) != 12 {
		t.Fatalf("paged attempts = %d, want 12", len(seen))
	}

	request.Subject.Login = "bob@example.test"
	if _, err := service.SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), request); !hasCode(err, supporthistory.CodeInvalidCursor) {
		t.Fatalf("cursor reuse for another subject error = %v, want INVALID_CURSOR", err)
	}
}

// hasCode reports whether err carries the service code.
func hasCode(err error, code supporthistory.ErrorCode) bool {
	var serviceErr *supporthistory.Error

	return errors.As(err, &serviceErr) && serviceErr.Code == code
}

// TestAuthorizationHappensBeforeAnyDataAccess pins that denied callers never reach the store.
func TestAuthorizationHappensBeforeAnyDataAccess(t *testing.T) {
	for name, who := range map[string]supporthistory.Caller{
		"zero value":   {},
		"admin scope":  caller(definitions.ScopeAdmin, definitions.ScopeSecurity, definitions.ScopeAuthenticate),
		"no client id": supporthistory.NewCaller(supporthistory.VerifiedCredential{Method: supporthistory.CredentialOIDCBearer, Scopes: []string{definitions.ScopeHistoryDetail}}),
		"other method": supporthistory.NewCaller(supporthistory.VerifiedCredential{Method: "basic", ClientID: "x", Scopes: []string{definitions.ScopeHistoryDetail}}),
	} {
		t.Run(name, func(t *testing.T) {
			store := fixtureStore(t)
			service := newService(t, store)

			_, searchErr := service.SearchAttempts(context.Background(), who, searchRequest())
			_, detailErr := service.GetAttempt(context.Background(), who, supporthistory.AttemptDetailRequest{
				SchemaVersion: "1", AttemptID: "rq1.req-cred", Around: scenarioBase,
				Subject: &supporthistory.Subject{Login: "anna@example.test"}})

			if !hasCode(searchErr, supporthistory.CodeForbidden) || !hasCode(detailErr, supporthistory.CodeForbidden) {
				t.Fatalf("errors = %v / %v, want FORBIDDEN", searchErr, detailErr)
			}

			if store.TotalCalls() != 0 {
				t.Fatalf("store calls = %v, want none before authorization", store.Calls)
			}
		})
	}
}

// TestDetailBindsTheAttemptToTheSubject pins that a guessed id of another subject reads like an unknown one.
func TestDetailBindsTheAttemptToTheSubject(t *testing.T) {
	service := newService(t, fixtureStore(t))
	detail := func(id string, subject *supporthistory.Subject, scope string) *supporthistory.AttemptDetailResult {
		result, err := service.GetAttempt(context.Background(), caller(scope), supporthistory.AttemptDetailRequest{
			SchemaVersion: "1", AttemptID: id, Around: scenarioBase.Add(-30 * time.Minute), Subject: subject})
		if err != nil {
			t.Fatalf("GetAttempt(%s) error = %v", id, err)
		}

		return result
	}

	anna := &supporthistory.Subject{Login: "anna@example.test"}
	if result := detail("rq1.req-bob", anna, definitions.ScopeHistoryRead); result.Attempt != nil {
		t.Fatalf("foreign attempt = %+v, want null", result.Attempt)
	}

	if result := detail("rq1.does-not-exist", anna, definitions.ScopeHistoryRead); result.Attempt != nil || result.ResultBasis != "no_matches" {
		t.Fatalf("unknown attempt = %+v, want null", result)
	}

	if result := detail("rq1.ss-1", &supporthistory.Subject{Account: "acc-anna"}, definitions.ScopeHistoryRead); result.Attempt == nil {
		t.Fatal("self-service step-up attempt must be reachable through its event account")
	}

	if result := detail("rq1.req-bob", nil, definitions.ScopeHistoryDetail); result.Attempt == nil {
		t.Fatal("detail role must reach an attempt without subject")
	}

	_, err := service.GetAttempt(context.Background(), caller(definitions.ScopeHistoryRead), supporthistory.AttemptDetailRequest{
		SchemaVersion: "1", AttemptID: "rq1.req-bob", Around: scenarioBase})
	if !hasCode(err, supporthistory.CodeInvalidRequest) {
		t.Fatalf("support detail without subject error = %v, want INVALID_REQUEST", err)
	}

	_, err = service.GetAttempt(context.Background(), caller(definitions.ScopeHistoryRead), supporthistory.AttemptDetailRequest{
		SchemaVersion: "1", AttemptID: "session-token-value", Around: scenarioBase, Subject: anna})
	if !hasCode(err, supporthistory.CodeInvalidAttemptID) {
		t.Fatalf("malformed id error = %v, want INVALID_ATTEMPT_ID", err)
	}
}
