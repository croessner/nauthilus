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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/historytest"
)

// completionNow is the query time of the completion scenarios (the service clock of newService).
var completionNow = scenarioBase.Add(time.Hour)

// completionBase is the start of finished completion scenarios: older than every code lifetime and export horizon.
var completionBase = completionNow.Add(-40 * time.Minute)

// flowRef returns a 32-character flow reference made of one repeated letter.
func flowRef(letter string) string {
	return strings.Repeat(letter, 32)
}

// oidcLogin is one contract password row of an OIDC authorization-code flow of the fixture subject.
func oidcLogin(at time.Time, flow, outcome, grant string) supporthistory.LoginRecord {
	record := subjectLogin(at, "req-"+flow[:1]+at.Format("150405"), flow, outcome, "", "")
	record.OutcomeStage, record.GrantType, record.OIDCClientID, record.Protocol = "auth_decision", grant, "webmail", "oidc"

	if outcome == "fail" {
		record.OutcomeMarker = "auth.outcome.auth_failure"
	}

	return record
}

// stepEvent is one auth_events row of the fixture subject inside a flow.
func stepEvent(at time.Time, flow, id, eventType, result, reason, effect string) supporthistory.AuthEventRecord {
	record := supporthistory.AuthEventRecord{At: at, EventID: id, EventType: eventType, EventVersion: 1, FlowRef: flow,
		RequestID: "rq-" + id, Protocol: "oidc", ClientID: "webmail", Account: "acc-anna", Result: result,
		Reason: reason, FlowEffect: effect}

	if eventType == "mfa.verification" {
		record.FactorRole, record.Method = "second_factor", "totp"
	}

	return record
}

// factorAccepted is an accepted second factor that completed the step-up of a flow.
func factorAccepted(at time.Time, flow string) supporthistory.AuthEventRecord {
	return stepEvent(at, flow, "mfa-"+flow[:1], "mfa.verification", "success", "verified", "step_up_completed")
}

// issued is the code issuance of a flow with the recorded authentication source.
func issued(at time.Time, flow, source string) supporthistory.AuthEventRecord {
	return stepEvent(at, flow, "iss-"+flow[:1], "oidc.code_issuance", "success", source, "code_issued")
}

// redeemed is one code redemption of a flow; every non-success result consumed the code.
func redeemed(at time.Time, flow, id, result, reason string) supporthistory.AuthEventRecord {
	effect := "code_consumed"
	if result == "success" {
		effect = "tokens_issued"
	}

	return stepEvent(at, flow, id, "oidc.code_redemption", result, reason, effect)
}

// completionStore extends the base fixture with OIDC completion scenarios; letters name the flows.
func completionStore(t *testing.T) *historytest.Store {
	t.Helper()

	store := fixtureStore(t)
	at := func(offset time.Duration) time.Time { return completionBase.Add(offset) }
	sec := time.Second

	store.Logins = append(store.Logins,
		oidcLogin(at(0), flowRef("a"), "ok", "authorization_code"),
		oidcLogin(at(0), flowRef("b"), "ok", "authorization_code"),
		oidcLogin(at(0), flowRef("c"), "ok", "authorization_code"),
		oidcLogin(at(0), flowRef("e"), "ok", "authorization_code"),
		oidcLogin(at(0), flowRef("f"), "ok", "authorization_code"),
		oidcLogin(at(0), flowRef("g"), "ok", "authorization_code"),
		oidcLogin(at(0), flowRef("h"), "ok", "authorization_code"),
		oidcLogin(at(-30*time.Minute), flowRef("l"), "ok", "authorization_code"),
		oidcLogin(at(0), flowRef("n"), "ok", "device_code"),
		oidcLogin(at(0), flowRef("o"), "fail", "authorization_code"),
		oidcLogin(at(0), flowRef("p"), "ok", "authorization_code"),
		oidcLogin(at(0), flowRef("r"), "fail", "authorization_code"),
	)

	latched := stepEvent(at(10*sec), flowRef("o"), "mfa-o", "mfa.verification", "invalid", "invalid_code", "none")
	latched.FailLatched = true
	latchedOnly := stepEvent(at(10*sec), flowRef("r"), "mfa-r", "mfa.verification", "invalid", "invalid_code", "none")
	latchedOnly.FailLatched = true
	unsupported := redeemed(at(30*sec), flowRef("p"), "red-p", "success", "tokens_issued")
	unsupported.EventVersion = 2

	store.Events = append(store.Events,
		// a: complete with MFA; b: the production case without completion events; c: complete without MFA.
		factorAccepted(at(20*sec), flowRef("a")), issued(at(25*sec), flowRef("a"), "authenticated_in_flow"),
		redeemed(at(26*sec), flowRef("a"), "red-a", "success", "tokens_issued"),
		factorAccepted(at(20*sec), flowRef("b")),
		issued(at(5*sec), flowRef("c"), "authenticated_in_flow"),
		redeemed(at(6*sec), flowRef("c"), "red-c", "success", "tokens_issued"),
		// d: reused SSO session without a login row.
		issued(at(0), flowRef("d"), "existing_session"), redeemed(at(sec), flowRef("d"), "red-d", "success", "tokens_issued"),
		// e: rejected after MFA; f: technical failure after the consume.
		factorAccepted(at(20*sec), flowRef("e")), issued(at(25*sec), flowRef("e"), "authenticated_in_flow"),
		redeemed(at(27*sec), flowRef("e"), "red-e", "rejected", "pkce_mismatch"),
		issued(at(25*sec), flowRef("f"), "authenticated_in_flow"),
		redeemed(at(27*sec), flowRef("f"), "red-f", "error", "token_issue_error"),
		// g: a failure that arrives with an earlier timestamp never undoes the recorded success.
		issued(at(10*sec), flowRef("g"), "authenticated_in_flow"),
		redeemed(at(26*sec), flowRef("g"), "red-g-ok", "success", "tokens_issued"),
		redeemed(at(20*sec), flowRef("g"), "red-g-late", "rejected", "client_mismatch"),
		// h: duplicate deliveries of the same events.
		issued(at(10*sec), flowRef("h"), "authenticated_in_flow"), issued(at(10*sec), flowRef("h"), "authenticated_in_flow"),
		redeemed(at(11*sec), flowRef("h"), "red-h", "success", "tokens_issued"),
		redeemed(at(11*sec), flowRef("h"), "red-h", "success", "tokens_issued"),
		// i: a code that may still be redeemed; j: a code that can no longer be redeemed.
		issued(completionNow.Add(-2*time.Minute), flowRef("i"), "existing_session"),
		issued(at(-5*time.Minute), flowRef("j"), "existing_session"),
		// k: the issuance event was lost; the redemption alone still proves the completion.
		redeemed(at(30*sec), flowRef("k"), "red-k", "success", "tokens_issued"),
		// m: a second factor of an OIDC flow without grant evidence; o: completion on a latched flow; p: unknown version.
		factorAccepted(at(20*sec), flowRef("m")),
		latched, issued(at(30*sec), flowRef("o"), "authenticated_in_flow"),
		unsupported,
		// r: a latched authorization-code flow is decided by the latch and has no completion to wait for.
		latchedOnly,
	)

	return store
}

// completionSearch searches the fixture subject up to the query time.
func completionSearch(t *testing.T, store *historytest.Store, scope string) (map[string]supporthistory.Attempt, *supporthistory.AttemptSearchResult) {
	t.Helper()

	request := searchRequest()
	request.Filter.Until = completionNow

	result, err := newService(t, store).SearchAttempts(context.Background(), caller(scope), request)
	if err != nil {
		t.Fatalf("SearchAttempts() error = %v", err)
	}

	byID := map[string]supporthistory.Attempt{}
	for _, attempt := range result.Attempts {
		byID[attempt.AttemptID] = attempt
	}

	return byID, result
}

// completionCase is the expected reading of one completion scenario.
type completionCase struct {
	flow, outcome, basis, progress, state, authentication, primary string
	final                                                          bool
	gaps                                                           []string
}

// TestCompletionSeparatesObservedFinalPendingExpiredAndUnknown pins the completion matrix of OIDC flows.
func TestCompletionSeparatesObservedFinalPendingExpiredAndUnknown(t *testing.T) {
	attempts, result := completionSearch(t, completionStore(t), definitions.ScopeHistoryRead)

	cases := []completionCase{
		{"a", "succeeded", "oidc_tokens_issued", "tokens_issued", "tokens_issued", "authenticated_in_flow", "recorded", true, nil},
		{"b", "not_observed", "none", "second_factor_completed", "code_issuance_not_observed", "unknown", "recorded", false,
			[]string{"FLOW_COMPLETION_NOT_OBSERVED"}},
		{"c", "succeeded", "oidc_tokens_issued", "tokens_issued", "tokens_issued", "authenticated_in_flow", "recorded", true, nil},
		{"d", "succeeded", "oidc_tokens_issued", "tokens_issued", "tokens_issued", "existing_session", "session_reused", true, nil},
		{"e", "rejected", "oidc_code_redemption_rejected", "authorization_code_issued", "redemption_rejected",
			"authenticated_in_flow", "recorded", true, nil},
		{"f", "technical_error", "oidc_code_redemption_failed", "authorization_code_issued", "redemption_failed",
			"authenticated_in_flow", "recorded", true, nil},
		{"g", "succeeded", "oidc_tokens_issued", "tokens_issued", "tokens_issued", "authenticated_in_flow", "recorded", true, nil},
		{"h", "succeeded", "oidc_tokens_issued", "tokens_issued", "tokens_issued", "authenticated_in_flow", "recorded", true, nil},
		{"i", "not_observed", "none", "authorization_code_issued", "redemption_pending", "existing_session", "session_reused",
			false, []string{"FLOW_COMPLETION_NOT_OBSERVED"}},
		{"j", "not_observed", "none", "authorization_code_issued", "code_expired_redemption_not_observed", "existing_session",
			"session_reused", false, []string{"FLOW_COMPLETION_NOT_OBSERVED"}},
		{"k", "succeeded", "oidc_tokens_issued", "tokens_issued", "tokens_issued", "unknown", "not_recorded", true,
			[]string{"PRIMARY_ROW_NOT_RECORDED"}},
		{"l", "not_observed", "none", "primary_succeeded", "not_recorded", "unknown", "recorded", false,
			[]string{"FLOW_COMPLETION_NEVER_RECORDED"}},
		{"p", "not_observed", "none", "primary_succeeded", "unknown", "unknown", "recorded", false,
			[]string{"FLOW_COMPLETION_NOT_OBSERVED"}},
	}

	for _, testCase := range cases {
		assertCompletion(t, attempts, testCase)
	}

	if result.History.CompletionEventsSince == nil ||
		!slices.Contains(result.History.KnownLimits, "FLOW_COMPLETION_RECORDED_FOR_OIDC_AUTHORIZATION_CODE_ONLY") ||
		slices.Contains(result.History.KnownLimits, "FLOW_COMPLETION_NEVER_RECORDED") {
		t.Fatalf("history = %+v, want the completion cutover and the narrowed limits", result.History)
	}
}

// assertCompletion compares one flow attempt with its expected completion reading.
func assertCompletion(t *testing.T, attempts map[string]supporthistory.Attempt, want completionCase) {
	t.Helper()

	attempt, ok := attempts["fl1."+flowRef(want.flow)]
	if !ok {
		t.Fatalf("flow %s missing from the search", want.flow)
	}

	if attempt.Outcome != want.outcome || attempt.OutcomeBasis != want.basis || attempt.Progress != want.progress ||
		attempt.FinalOutcomeObserved != want.final || attempt.Completion == nil ||
		attempt.Completion.State != want.state || attempt.Completion.Authentication != want.authentication ||
		attempt.Steps.Primary != want.primary {
		t.Fatalf("flow %s = outcome %s/%s/%s final %v steps %+v completion %+v", want.flow, attempt.Outcome,
			attempt.OutcomeBasis, attempt.Progress, attempt.FinalOutcomeObserved, attempt.Steps, attempt.Completion)
	}

	gaps := append([]string{}, want.gaps...)
	if !slices.Equal(attempt.Recording.KnownGaps, gaps) {
		t.Fatalf("flow %s gaps = %v, want %v", want.flow, attempt.Recording.KnownGaps, gaps)
	}
}

// completeFlowDetails checks the four separate milestones of a complete flow and their own stages.
func completeFlowDetails(attempt supporthistory.Attempt) bool {
	codes := []string{supporthistory.CodePrimarySucceeded, supporthistory.CodeFactorAccepted,
		supporthistory.CodeAuthorizationCodeIssued, supporthistory.CodeTokensIssued}
	steps := supporthistory.Steps{Primary: "recorded", SecondFactor: "recorded", CodeIssuance: "recorded",
		CodeRedemption: "recorded"}

	if !slices.Equal(eventCodes(attempt), codes) || attempt.Steps != steps || len(attempt.Findings) != 0 {
		return false
	}

	return attempt.Events[2].Stage == "authorization" && attempt.Events[3].Stage == "token_exchange" &&
		attempt.Events[2].Factor == nil && attempt.Events[3].Factor == nil
}

// expiredCodeDetails checks the recorded issuance time and the version lifetime of an unredeemed code.
func expiredCodeDetails(attempt supporthistory.Attempt) bool {
	expired := attempt.Completion

	return expired.CodeIssuedAt != nil && expired.CodeRedeemableUntil != nil &&
		expired.CodeRedeemableUntil.Sub(*expired.CodeIssuedAt) == 10*time.Minute && expired.RedemptionObservedAt == nil
}

// findingsAre returns a check for the exact finding codes of an attempt.
func findingsAre(codes ...string) func(supporthistory.Attempt) bool {
	return func(attempt supporthistory.Attempt) bool { return slices.Equal(findingCodes(attempt), codes) }
}

// TestCompletionDetailsOfOneFlow pins steps, times, merged duplicates, and the findings of completion events.
func TestCompletionDetailsOfOneFlow(t *testing.T) {
	attempts, _ := completionSearch(t, completionStore(t), definitions.ScopeHistoryRead)

	checks := map[string]func(supporthistory.Attempt) bool{
		"a": completeFlowDetails,
		"c": func(attempt supporthistory.Attempt) bool {
			return attempt.Steps.SecondFactor == "not_recorded" && attempt.Progress == "tokens_issued"
		},
		"e": findingsAre(supporthistory.CodeRedemptionPKCEFailed),
		"g": findingsAre(supporthistory.CodeRedemptionClientMismatch),
		"h": func(attempt supporthistory.Attempt) bool {
			return attempt.Recording.ReplayedRowsMerged == 2 && len(attempt.Events) == 3
		},
		"j": expiredCodeDetails,
		"k": func(attempt supporthistory.Attempt) bool {
			return attempt.Steps.CodeIssuance == "not_recorded" && attempt.Steps.CodeRedemption == "recorded"
		},
		"p": func(attempt supporthistory.Attempt) bool {
			return slices.Contains(findingCodes(attempt), supporthistory.CodeUnsupportedEventVersion)
		},
	}

	for letter, check := range checks {
		if attempt := attempts["fl1."+flowRef(letter)]; !check(attempt) {
			t.Fatalf("flow %s = codes %v steps %+v completion %+v findings %+v recording %+v", letter,
				eventCodes(attempt), attempt.Steps, attempt.Completion, attempt.Findings, attempt.Recording)
		}
	}

	if rejected := attempts["fl1."+flowRef("e")]; rejected.Findings[0].Category != "client_request" {
		t.Fatalf("rejected redemption category = %s, want client_request", rejected.Findings[0].Category)
	}
}

// TestCompletionNeverAppliesOutsideAuthorizationCodeFlows pins the flows without completion block (device-code,
// undeterminable grants, latched flows) and that completion events contradicting a latch stay unknown.
func TestCompletionNeverAppliesOutsideAuthorizationCodeFlows(t *testing.T) {
	attempts, _ := completionSearch(t, completionStore(t), definitions.ScopeHistoryDetail)

	cases := []struct {
		flow, outcome string
		gaps          []string
		block         bool
	}{
		{"m", "not_observed", []string{"PRIMARY_ROW_NOT_RECORDED", "FLOW_COMPLETION_SCOPE_UNDETERMINED"}, false},
		{"n", "not_observed", []string{"FLOW_COMPLETION_NEVER_RECORDED"}, false},
		{"o", "unknown", []string{"CONFLICTING_TERMINAL_RECORDS"}, true},
		{"r", "rejected", []string{}, false},
	}

	for _, testCase := range cases {
		attempt := attempts["fl1."+flowRef(testCase.flow)]
		if attempt.Outcome != testCase.outcome || (attempt.Completion != nil) != testCase.block ||
			!slices.Equal(attempt.Recording.KnownGaps, testCase.gaps) {
			t.Fatalf("flow %s = outcome %s completion %+v gaps %v", testCase.flow, attempt.Outcome, attempt.Completion,
				attempt.Recording.KnownGaps)
		}
	}

	if fixtureFlow := attempts["fl1."+strings.Repeat("1", 32)]; fixtureFlow.Completion != nil ||
		fixtureFlow.Steps.CodeIssuance != "not_applicable" {
		t.Fatalf("fixture flow without grant evidence = %+v", fixtureFlow.Steps)
	}
}

// TestOldDataKeepsTheNeverRecordedReading pins that a deployment without completion events keeps every existing gap
// and limit, also for flows with authorization-code evidence.
func TestOldDataKeepsTheNeverRecordedReading(t *testing.T) {
	store := fixtureStore(t)
	store.Logins = append(store.Logins, oidcLogin(scenarioBase.Add(-10*time.Minute), flowRef("q"), "ok", "authorization_code"))
	store.Events = append(store.Events, factorAccepted(scenarioBase.Add(-9*time.Minute), flowRef("q")))

	attempts, result := completionSearch(t, store, definitions.ScopeHistoryRead)
	legacy := attempts["fl1."+flowRef("q")]

	if legacy.Outcome != "not_observed" || legacy.Completion == nil || legacy.Completion.State != "not_recorded" ||
		!slices.Equal(legacy.Recording.KnownGaps, []string{"FLOW_COMPLETION_NEVER_RECORDED"}) {
		t.Fatalf("old flow = %+v completion %+v", legacy.Recording, legacy.Completion)
	}

	if result.History.CompletionEventsSince != nil ||
		!slices.Contains(result.History.KnownLimits, "FLOW_COMPLETION_NEVER_RECORDED") {
		t.Fatalf("history = %+v, want the never-recorded limit", result.History)
	}
}

// TestCompletionProbeFailureStaysConservative pins that an unknown cutover never upgrades a flow to "recorded".
func TestCompletionProbeFailureStaysConservative(t *testing.T) {
	store := completionStore(t)
	store.Errors = map[string]error{"CompletionEventsSince": supporthistory.ErrSourceUnavailable}

	attempts, result := completionSearch(t, store, definitions.ScopeHistoryRead)

	if production := attempts["fl1."+flowRef("b")]; production.Completion.State != "not_recorded" ||
		!slices.Equal(production.Recording.KnownGaps, []string{"FLOW_COMPLETION_NEVER_RECORDED"}) {
		t.Fatalf("flow without completion events = %+v", production.Completion)
	}

	if complete := attempts["fl1."+flowRef("a")]; complete.Completion.State != "tokens_issued" {
		t.Fatalf("observed completion = %+v, want it independent of the probe", complete.Completion)
	}

	if !slices.Contains(result.History.Conditions, "COMPLETION_CUTOVER_UNKNOWN") {
		t.Fatalf("conditions = %v", result.History.Conditions)
	}
}

// TestSessionReusedFlowsAnchorFilteredSearches pins that a flow without login row is found through its events, also
// with protocol and client filters, and that its identity is released to the support role.
func TestSessionReusedFlowsAnchorFilteredSearches(t *testing.T) {
	request := searchRequest()
	request.Filter.Until = completionNow
	request.Filter.Protocol, request.Filter.OIDCClientID = "oidc", "webmail"

	result, err := newService(t, completionStore(t)).SearchAttempts(context.Background(),
		caller(definitions.ScopeHistoryRead), request)
	if err != nil {
		t.Fatalf("SearchAttempts() error = %v", err)
	}

	index := slices.IndexFunc(result.Attempts, func(a supporthistory.Attempt) bool { return a.AttemptID == "fl1."+flowRef("d") })
	if index < 0 {
		t.Fatal("the reused-session flow is missing from a filtered search")
	}

	for _, event := range result.Attempts[index].Events {
		if event.Identity.Redacted || stringValue(event.Identity.CanonicalAccount) != "acc-anna" {
			t.Fatalf("support event identity = %+v, want the subject released", event.Identity)
		}
	}
}

// stringValue dereferences an optional string in tests.
func stringValue(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}
