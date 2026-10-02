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

package core

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyfsm "github.com/croessner/nauthilus/v4/server/policy/fsm"
	"github.com/croessner/nauthilus/v4/server/policy/report"
	"github.com/croessner/nauthilus/v4/server/rediscli"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/prometheus/client_golang/prometheus"
	lua "github.com/yuin/gopher-lua"
)

// authnFSMGuardViolationMetric is the bounded host counter of policy permits the auth FSM rejected.
const authnFSMGuardViolationMetric = "authn_fsm_guard_violations_total"

// authnFSMGuardVerifier answers backend verification with one fixed host verdict.
type authnFSMGuardVerifier struct {
	err           error
	authenticated bool
	userFound     bool
}

// Verify returns the configured verdict as a request-owned backend result.
func (v authnFSMGuardVerifier) Verify(_ *gin.Context, auth *AuthState, _ []*PassDBMap) (*PassDBResult, error) {
	if v.err != nil {
		return nil, v.err
	}

	result := GetPassDBResultFromPool()
	result.Authenticated = v.authenticated
	result.UserFound = v.userFound
	result.AccountField = "uid"
	result.Account = auth.Request.Username
	result.Backend = definitions.BackendTest
	result.Attributes = map[string][]any{"uid": {auth.Request.Username}}

	return result, nil
}

// authnFSMGuardFlippingSubject is a subject source that tries to turn a failed verification into a success.
type authnFSMGuardFlippingSubject struct{}

// AnalyzeSource patches the shared backend result and request state to authenticated.
func (authnFSMGuardFlippingSubject) AnalyzeSource(
	_ *gin.Context,
	view *StateView,
	result *PassDBResult,
	_ string,
	_ *lua.FunctionProto,
	_ *vmpool.Manager,
	_ vmpool.PoolKey,
	_ *luaseal.Modules,
) definitions.AuthResult {
	result.Authenticated = true
	view.Auth().Runtime.Authenticated = true

	return definitions.AuthResultOK
}

// authnFSMGuardLogBuffer collects one request's structured log lines.
type authnFSMGuardLogBuffer struct {
	buffer bytes.Buffer
	mu     sync.Mutex
}

// Write appends one log record.
func (b *authnFSMGuardLogBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.Write(value)
}

// String returns every collected log record.
func (b *authnFSMGuardLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.String()
}

// authnFSMGuardHarness owns one response-capturing candidate request and its log output.
type authnFSMGuardHarness struct {
	execution *authnCandidateExecution
	logs      *authnFSMGuardLogBuffer
	operation policy.Operation
}

// newAuthnFSMGuardHarness prepares one candidate request whose host services answer with verifier and subject.
func newAuthnFSMGuardHarness(
	t *testing.T,
	operation policy.Operation,
	verifier PasswordVerifier,
	subject CapturedLuaSubject,
) *authnFSMGuardHarness {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	db, _ := redismock.NewClientMock()
	logs := &authnFSMGuardLogBuffer{}
	host := newAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger:        slog.New(slog.NewTextHandler(logs, nil)),
		Redis:         rediscli.NewTestClient(db),
		AccountCache:  accountcache.NewManager(cfg),
		HostServices:  newTestAuthnHostServices(t, verifier, subject),
		NativeRuntime: authnCapturedNativeRuntime{},

		BackendAuthenticationCache: NewPositiveBackendAuthenticationCache(time.Now),
	})

	input := normalizeAuthInput(authnApplicationTestInput(authModeForOperation(operation)), authModeForOperation(operation))
	ctx, gate := authnCandidateTestContext(context.Background(), input)

	execution, _, err := host.prepareAuthnCandidateExecution(ctx, input, operation)
	if err != nil {
		t.Fatalf("prepareAuthnCandidateExecution() error = %v", err)
	}

	t.Cleanup(func() {
		execution.release()
		gate.Complete()
	})

	return &authnFSMGuardHarness{execution: execution, logs: logs, operation: operation}
}

// runBackend executes the request's backend checkpoint without a positive password cache.
func (h *authnFSMGuardHarness) runBackend(t *testing.T) {
	t.Helper()

	h.runBackendPlan(t, backendExecutionPlan{})
}

// runBackendPlan executes the request's backend checkpoint with one backend execution plan.
func (h *authnFSMGuardHarness) runBackendPlan(t *testing.T, plan backendExecutionPlan) {
	t.Helper()

	if _, err := h.execution.prepareBackendPlan(plan); err != nil {
		t.Fatalf("prepareBackendPlan() error = %v", err)
	}
}

// completeSubject finishes the subject checkpoint exactly as the scheduler does after every subject provider.
func (h *authnFSMGuardHarness) completeSubject() {
	h.execution.completeSubjectCheckpoint()
}

// finalize selects one rule at stage and applies the checkpoint response for its decision.
func (h *authnFSMGuardHarness) finalize(
	t *testing.T,
	stage policy.Stage,
	selected policy.Decision,
	marker string,
) authnApplicationResult {
	t.Helper()

	checkpoint := string(policy.StageAuthDecision)
	if stage == policy.StagePreAuth {
		checkpoint = string(policy.StagePreAuth)
	}

	h.execution.CaptureAuthnDecision(context.Background(), decision.Target{}, checkpoint, &report.FinalDecision{
		PolicyName: "configured_outcome", Stage: stage, Effect: selected, FSMEventMarker: marker,
	})

	result, err := h.execution.finalize(
		checkpoint,
		mustAuthnDecisionResponse(t, authnFSMGuardEffect(selected)),
		h.execution.currentResult(),
	)
	if err != nil {
		t.Fatalf("finalize() error = %v", err)
	}

	return result
}

// authnFSMGuardEffect maps an authn rule decision to the checkpoint response effect.
func authnFSMGuardEffect(selected policy.Decision) decision.Effect {
	switch selected {
	case policy.DecisionPermit:
		return decision.EffectPermit
	case policy.DecisionDeny:
		return decision.EffectDeny
	case policy.DecisionTempFail:
		return decision.EffectIndeterminate
	default:
		return decision.EffectNotApplicable
	}
}

// authnFSMGuardOutcome projects decision, terminal state, and FSM path of either operation outcome.
func authnFSMGuardOutcome(result authnApplicationResult) (AuthDecision, string, []string) {
	if result.accounts != nil {
		return result.accounts.Decision, result.accounts.TerminalState, result.accounts.FSMEventPath
	}

	if result.auth != nil {
		return result.auth.Decision, result.auth.TerminalState, result.auth.FSMEventPath
	}

	return AuthDecisionUnset, "", nil
}

// authnFSMGuardViolations returns the current guard counter for one operation and checkpoint.
func authnFSMGuardViolations(t *testing.T, operation policy.Operation, checkpoint string) float64 {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, family := range families {
		if family.GetName() != authnFSMGuardViolationMetric {
			continue
		}

		for _, metric := range family.GetMetric() {
			labels := make(map[string]string, len(metric.GetLabel()))
			for _, label := range metric.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}

			if labels["operation"] == string(operation) && labels["checkpoint"] == checkpoint {
				return metric.GetCounter().GetValue()
			}
		}
	}

	return 0
}

// authnFSMGuardHostPath returns the host-owned FSM prefix followed by one terminal event.
func authnFSMGuardHostPath(operation policy.Operation, terminal string) []string {
	evaluated := policy.FSMEventMarkerAuthEvaluated
	if operation == policy.OperationListAccounts {
		evaluated = policy.FSMEventMarkerAccountProviderEvaluated
	}

	return []string{policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthOK, evaluated, terminal}
}

// authnFSMGuardCase binds host evidence and one policy selection to the response the auth FSM must enforce.
type authnFSMGuardCase struct {
	prepare       func(*testing.T, *authnFSMGuardHarness)
	verifier      PasswordVerifier
	subject       CapturedLuaSubject
	name          string
	operation     policy.Operation
	stage         policy.Stage
	selected      policy.Decision
	marker        string
	wantDecision  AuthDecision
	wantTerminal  string
	wantPath      []string
	wantViolation bool
}

// authnFSMGuardPermitCases lists policy permits with and without the host evidence they require.
func authnFSMGuardPermitCases() []authnFSMGuardCase {
	authenticated := authnFSMGuardVerifier{authenticated: true, userFound: true}
	rejected := authnFSMGuardVerifier{userFound: true}
	permitted := authnFSMGuardHostPath(policy.OperationAuthenticate, policy.FSMEventMarkerAuthPermit)
	guarded := authnFSMGuardHostPath(policy.OperationAuthenticate, policy.FSMEventMarkerAuthTempFail)

	return []authnFSMGuardCase{
		{
			name: "permit with an authenticated backend answers ok", operation: policy.OperationAuthenticate,
			verifier: authenticated, prepare: runAuthnFSMGuardBackendAndSubject,
			wantDecision: AuthDecisionOK, wantTerminal: policyfsm.StateAuthOK, wantPath: permitted,
		},
		{
			name: "permit after a failed password check is guarded", operation: policy.OperationAuthenticate,
			verifier: rejected, prepare: runAuthnFSMGuardBackendAndSubject,
			wantDecision: AuthDecisionTempFail, wantTerminal: policyfsm.StateAuthTempFail, wantPath: guarded,
			wantViolation: true,
		},
		{
			name: "permit after a backend failure is guarded", operation: policy.OperationAuthenticate,
			verifier: authnFSMGuardVerifier{err: errors.New("backend unavailable")}, prepare: runAuthnFSMGuardBackend,
			wantDecision: AuthDecisionTempFail, wantTerminal: policyfsm.StateAuthTempFail, wantPath: guarded,
			wantViolation: true,
		},
		{
			name: "permit without any backend verification is guarded", operation: policy.OperationAuthenticate,
			verifier:     authenticated,
			wantDecision: AuthDecisionTempFail, wantTerminal: policyfsm.StateAuthTempFail, wantPath: guarded,
			wantViolation: true,
		},
		{
			name: "permit after a Lua subject flipped a failed check is guarded", operation: policy.OperationAuthenticate,
			verifier: rejected, subject: authnFSMGuardFlippingSubject{}, prepare: runAuthnFSMGuardLuaSubjectFlip,
			wantDecision: AuthDecisionTempFail, wantTerminal: policyfsm.StateAuthTempFail, wantPath: guarded,
			wantViolation: true,
		},
		{
			name: "permit after a native subject patched a failed check is guarded", operation: policy.OperationAuthenticate,
			verifier: rejected, prepare: runAuthnFSMGuardNativeSubjectPatch,
			wantDecision: AuthDecisionTempFail, wantTerminal: policyfsm.StateAuthTempFail, wantPath: guarded,
			wantViolation: true,
		},
		{
			name: "permit with a positive backend cache hit answers ok", operation: policy.OperationAuthenticate,
			verifier: rejected, prepare: runAuthnFSMGuardPositiveCacheHit,
			wantDecision: AuthDecisionOK, wantTerminal: policyfsm.StateAuthOK, wantPath: permitted,
		},
	}
}

// authnFSMGuardIdentityCases lists identity lookups and account listings with and without host evidence.
func authnFSMGuardIdentityCases() []authnFSMGuardCase {
	return []authnFSMGuardCase{
		{
			name: "lookup_identity permit with a found identity answers ok", operation: policy.OperationLookupIdentity,
			verifier: authnFSMGuardVerifier{authenticated: true, userFound: true}, prepare: runAuthnFSMGuardBackendAndSubject,
			wantDecision: AuthDecisionOK, wantTerminal: policyfsm.StateAuthOK,
			wantPath: authnFSMGuardHostPath(policy.OperationLookupIdentity, policy.FSMEventMarkerAuthPermit),
		},
		{
			name: "lookup_identity permit without a found identity is guarded", operation: policy.OperationLookupIdentity,
			verifier: authnFSMGuardVerifier{}, prepare: runAuthnFSMGuardBackendAndSubject,
			wantDecision: AuthDecisionTempFail, wantTerminal: policyfsm.StateAuthTempFail,
			wantPath:      authnFSMGuardHostPath(policy.OperationLookupIdentity, policy.FSMEventMarkerAuthTempFail),
			wantViolation: true,
		},
		{
			name: "list_accounts permit after the account provider answers ok", operation: policy.OperationListAccounts,
			verifier: authnFSMGuardVerifier{}, prepare: runAuthnFSMGuardAccountProvider,
			wantDecision: AuthDecisionOK, wantTerminal: policyfsm.StateAuthOK,
			wantPath: authnFSMGuardHostPath(policy.OperationListAccounts, policy.FSMEventMarkerAuthPermit),
		},
		{
			name: "list_accounts permit without the account provider is guarded", operation: policy.OperationListAccounts,
			verifier:     authnFSMGuardVerifier{},
			wantDecision: AuthDecisionTempFail, wantTerminal: policyfsm.StateAuthTempFail,
			wantPath:      authnFSMGuardHostPath(policy.OperationListAccounts, policy.FSMEventMarkerAuthTempFail),
			wantViolation: true,
		},
	}
}

// authnFSMGuardTighteningCases lists deny and tempfail selections, which pass through regardless of host evidence.
func authnFSMGuardTighteningCases() []authnFSMGuardCase {
	authenticated := authnFSMGuardVerifier{authenticated: true, userFound: true}

	return []authnFSMGuardCase{
		{
			name: "deny after an authenticated backend answers fail", operation: policy.OperationAuthenticate,
			verifier: authenticated, prepare: runAuthnFSMGuardBackendAndSubject,
			selected: policy.DecisionDeny, marker: policy.FSMEventMarkerAuthDeny,
			wantDecision: AuthDecisionFail, wantTerminal: policyfsm.StateAuthFail,
			wantPath: authnFSMGuardHostPath(policy.OperationAuthenticate, policy.FSMEventMarkerAuthDeny),
		},
		{
			name: "unmarked deny derives the auth_deny event", operation: policy.OperationAuthenticate,
			verifier: authenticated, prepare: runAuthnFSMGuardBackendAndSubject, selected: policy.DecisionDeny,
			wantDecision: AuthDecisionFail, wantTerminal: policyfsm.StateAuthFail,
			wantPath: authnFSMGuardHostPath(policy.OperationAuthenticate, policy.FSMEventMarkerAuthDeny),
		},
		{
			name: "tempfail after an authenticated backend answers tempfail", operation: policy.OperationAuthenticate,
			verifier: authenticated, prepare: runAuthnFSMGuardBackendAndSubject,
			selected: policy.DecisionTempFail, marker: policy.FSMEventMarkerAuthTempFail,
			wantDecision: AuthDecisionTempFail, wantTerminal: policyfsm.StateAuthTempFail,
			wantPath: authnFSMGuardHostPath(policy.OperationAuthenticate, policy.FSMEventMarkerAuthTempFail),
		},
		{
			name: "list_accounts deny answers fail", operation: policy.OperationListAccounts,
			verifier: authenticated, prepare: runAuthnFSMGuardAccountProvider,
			selected: policy.DecisionDeny, marker: policy.FSMEventMarkerAuthDeny,
			wantDecision: AuthDecisionFail, wantTerminal: policyfsm.StateAuthFail,
			wantPath: authnFSMGuardHostPath(policy.OperationListAccounts, policy.FSMEventMarkerAuthDeny),
		},
		{
			name: "pre_auth deny answers fail", operation: policy.OperationAuthenticate, verifier: authenticated,
			stage: policy.StagePreAuth, selected: policy.DecisionDeny, marker: policy.FSMEventMarkerPreAuthDeny,
			wantDecision: AuthDecisionFail, wantTerminal: policyfsm.StateAuthFail,
			wantPath: []string{policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthDeny},
		},
		{
			name: "pre_auth tempfail answers tempfail", operation: policy.OperationAuthenticate, verifier: authenticated,
			stage: policy.StagePreAuth, selected: policy.DecisionTempFail, marker: policy.FSMEventMarkerPreAuthTempFail,
			wantDecision: AuthDecisionTempFail, wantTerminal: policyfsm.StateAuthTempFail,
			wantPath: []string{policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthTempFail},
		},
	}
}

// runAuthnFSMGuardBackend executes only the backend checkpoint.
func runAuthnFSMGuardBackend(t *testing.T, h *authnFSMGuardHarness) {
	t.Helper()

	h.runBackend(t)
}

// runAuthnFSMGuardBackendAndSubject executes the backend checkpoint and completes the subject checkpoint.
func runAuthnFSMGuardBackendAndSubject(t *testing.T, h *authnFSMGuardHarness) {
	t.Helper()

	h.runBackend(t)
	h.completeSubject()
}

// runAuthnFSMGuardLuaSubjectFlip lets a Lua subject source flip a failed verification before completion.
func runAuthnFSMGuardLuaSubjectFlip(t *testing.T, h *authnFSMGuardHarness) {
	t.Helper()

	h.runBackend(t)

	if _, err := h.execution.prepareLuaSubjectSource("flip", &lua.FunctionProto{}, nil, "", nil); err != nil {
		t.Fatalf("prepareLuaSubjectSource() error = %v", err)
	}

	h.completeSubject()
}

// runAuthnFSMGuardNativeSubjectPatch lets a native subject source patch a failed verification to authenticated.
func runAuthnFSMGuardNativeSubjectPatch(t *testing.T, h *authnFSMGuardHarness) {
	t.Helper()

	h.runBackend(t)
	h.patchNativeSubjectAuthenticated(t)
	h.completeSubject()
}

// patchNativeSubjectAuthenticated runs one native subject source whose backend result patch sets authenticated.
func (h *authnFSMGuardHarness) patchNativeSubjectAuthenticated(t *testing.T) {
	t.Helper()

	authenticated := true
	provider := &authnCapturedNativeSubjectSource{
		id: "authn/plugin.example.subject.flip", patch: &pluginapi.BackendResultPatch{Authenticated: &authenticated},
	}

	if _, err := h.execution.prepareNativeSubjectSource(provider.id, provider); err != nil {
		t.Fatalf("prepareNativeSubjectSource() error = %v", err)
	}
}

// runAuthnFSMGuardPositiveCacheHit serves the backend checkpoint from a positive in-memory authentication.
func runAuthnFSMGuardPositiveCacheHit(t *testing.T, h *authnFSMGuardHarness) {
	t.Helper()

	verified, err := authnFSMGuardVerifier{authenticated: true, userFound: true}.Verify(h.execution.ginCtx, h.execution.auth, nil)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	verified.Backend = definitions.BackendLDAP

	cache := h.execution.auth.backendAuthenticationCache()
	stored := cache.StoreForRequest(h.execution.ginCtx, h.execution.auth, verified, time.Minute, h.execution.auth.Request.Username)
	PutPassDBResultToPool(verified)

	if !stored {
		t.Fatal("positive backend authentication was not cached")
	}

	h.runBackend(t)

	if !h.execution.backendCached {
		t.Fatal("backend checkpoint did not use the positive cache")
	}

	h.completeSubject()
}

// runAuthnFSMGuardAccountProvider executes the account provider.
func runAuthnFSMGuardAccountProvider(_ *testing.T, h *authnFSMGuardHarness) {
	h.execution.prepareAccountProvider()
}

// TestAuthnFSMGuardEnforcesHostEvidence proves the auth FSM, driven by host evidence, decides whether a policy permit
// may answer ok, while deny and tempfail always pass, and that response, terminal state, and telemetry agree.
func TestAuthnFSMGuardEnforcesHostEvidence(t *testing.T) {
	cases := append(authnFSMGuardPermitCases(), authnFSMGuardIdentityCases()...)
	cases = append(cases, authnFSMGuardTighteningCases()...)

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if test.stage == "" {
				test.stage = policy.StageAuthDecision
			}

			if test.selected == "" {
				test.selected, test.marker = policy.DecisionPermit, policy.FSMEventMarkerAuthPermit
			}

			if test.subject == nil {
				test.subject = testLuaSubject{}
			}

			harness := newAuthnFSMGuardHarness(t, test.operation, test.verifier, test.subject)
			if test.prepare != nil {
				test.prepare(t, harness)
			}

			before := authnFSMGuardViolations(t, test.operation, string(test.stage))
			result := harness.finalize(t, test.stage, test.selected, test.marker)

			assertAuthnFSMGuardOutcome(t, harness, result, test)
			assertAuthnFSMGuardViolation(t, harness, test, authnFSMGuardViolations(t, test.operation, string(test.stage))-before)
		})
	}
}

// assertAuthnFSMGuardOutcome requires response, outcome terminal state, and recorded FSM telemetry to agree.
func assertAuthnFSMGuardOutcome(
	t *testing.T,
	harness *authnFSMGuardHarness,
	result authnApplicationResult,
	test authnFSMGuardCase,
) {
	t.Helper()

	gotDecision, gotTerminal, gotPath := authnFSMGuardOutcome(result)
	if gotDecision != test.wantDecision {
		t.Fatalf("decision = %q, want %q", gotDecision, test.wantDecision)
	}

	if gotTerminal != test.wantTerminal {
		t.Fatalf("outcome terminal state = %q, want %q", gotTerminal, test.wantTerminal)
	}

	runtime := harness.execution.auth.Runtime
	if runtime.AuthFSMTerminalState != test.wantTerminal {
		t.Fatalf("recorded FSM terminal state = %q, want %q", runtime.AuthFSMTerminalState, test.wantTerminal)
	}

	if !slices.Equal(runtime.AuthFSMEventPath, test.wantPath) || !slices.Equal(gotPath, test.wantPath) {
		t.Fatalf("FSM path recorded=%v outcome=%v, want %v", runtime.AuthFSMEventPath, gotPath, test.wantPath)
	}

	if aborted := harness.execution.ginCtx.IsAborted(); aborted != (test.wantDecision != AuthDecisionOK) {
		t.Fatalf("request aborted = %t, want %t for %q", aborted, test.wantDecision != AuthDecisionOK, test.wantDecision)
	}
}

// assertAuthnFSMGuardViolation requires exactly one counted and logged violation for each guarded permit.
func assertAuthnFSMGuardViolation(t *testing.T, harness *authnFSMGuardHarness, test authnFSMGuardCase, counted float64) {
	t.Helper()

	want := 0.0
	if test.wantViolation {
		want = 1
	}

	if counted != want {
		t.Fatalf("guard violations counted = %v, want %v", counted, want)
	}

	logs := harness.logs.String()
	logged := strings.Contains(logs, "level=ERROR") && strings.Contains(logs, "auth FSM guard")

	if logged != test.wantViolation {
		t.Fatalf("guard violation logged = %t, want %t: %s", logged, test.wantViolation, logs)
	}

	if !test.wantViolation {
		return
	}

	for _, part := range []string{harness.execution.auth.Runtime.GUID, "operation=" + string(test.operation)} {
		if !strings.Contains(logs, part) {
			t.Fatalf("guard violation log lacks %q: %s", part, logs)
		}
	}

	if strings.Contains(logs, "must-never-be-a-policy-fact") {
		t.Fatalf("guard violation log leaks the credential: %s", logs)
	}
}

// authnFSMGuardRecordingCache counts positive password cache updates.
type authnFSMGuardRecordingCache struct {
	successes atomic.Int32
	failures  atomic.Int32
}

// OnSuccess records one positive cache write.
func (c *authnFSMGuardRecordingCache) OnSuccess(*AuthState, string) error {
	c.successes.Add(1)

	return nil
}

// OnFailure records one failed authentication cache update.
func (c *authnFSMGuardRecordingCache) OnFailure(*AuthState, string) {
	c.failures.Add(1)
}

// Purge ignores cache invalidation in this fixture.
func (*authnFSMGuardRecordingCache) Purge(*AuthState, string) {}

// TestAuthnSubjectCannotRaiseCredentialIntoPositivePasswordCache proves a subject patch cannot store a failed
// password as a positive cache entry, which would let a later request with the same password pass as verified.
func TestAuthnSubjectCannotRaiseCredentialIntoPositivePasswordCache(t *testing.T) {
	plan := backendExecutionPlan{
		positions:                map[definitions.Backend]int{definitions.BackendCache: 0, definitions.BackendLDAP: 1},
		hasPositivePasswordCache: true,
	}

	tests := []struct {
		verifier      PasswordVerifier
		name          string
		wantSuccesses int32
		wantFailures  int32
	}{
		{name: "verified credential is cached", verifier: authnFSMGuardVerifier{authenticated: true, userFound: true}, wantSuccesses: 1},
		{name: "patched failed credential is not cached", verifier: authnFSMGuardVerifier{userFound: true}, wantFailures: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache := &authnFSMGuardRecordingCache{}
			harness := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate, test.verifier, testLuaSubject{})
			harness.execution.auth.deps.HostServices.cache = cache

			harness.runBackendPlan(t, plan)
			harness.execution.auth.Runtime.UsedPassDBBackend = definitions.BackendLDAP
			harness.patchNativeSubjectAuthenticated(t)
			harness.completeSubject()

			if cache.successes.Load() != test.wantSuccesses || cache.failures.Load() != test.wantFailures {
				t.Fatalf("positive cache successes=%d failures=%d, want %d/%d",
					cache.successes.Load(), cache.failures.Load(), test.wantSuccesses, test.wantFailures)
			}
		})
	}
}

// TestAuthnHostEvidenceFreezesFirstVerdictAndNeverRaises pins the evidence contract the auth FSM guard relies on.
func TestAuthnHostEvidenceFreezesFirstVerdictAndNeverRaises(t *testing.T) {
	var evidence authnHostEvidence

	if evidence.permits(policy.OperationAuthenticate) || evidence.permits(policy.OperationListAccounts) {
		t.Fatal("unobserved evidence permits")
	}

	evidence.freezeCredential(definitions.AuthResultFail)
	evidence.freezeCredential(definitions.AuthResultOK)
	evidence.lowerCredential(definitions.AuthResultOK)

	if evidence.permits(policy.OperationAuthenticate) || evidence.permits(policy.OperationLookupIdentity) {
		t.Fatal("a failed credential verdict was raised")
	}

	if evidence.hostEvent(policy.OperationAuthenticate) != policy.FSMEventMarkerAuthDeny {
		t.Fatalf("host event = %q, want %q", evidence.hostEvent(policy.OperationAuthenticate), policy.FSMEventMarkerAuthDeny)
	}

	if evidence.permits(policy.OperationListAccounts) {
		t.Fatal("credential evidence backs an account listing")
	}

	evidence.freezeAccounts(definitions.AuthResultOK)

	if !evidence.permits(policy.OperationListAccounts) || evidence.permits(policy.OperationAuthenticate) {
		t.Fatal("account provider evidence crossed into the credential verdict")
	}

	failedListing := authnHostEvidence{}
	failedListing.freezeAccounts(definitions.AuthResultTempFail)
	failedListing.freezeAccounts(definitions.AuthResultOK)

	if failedListing.permits(policy.OperationListAccounts) {
		t.Fatal("a failed account provider verdict was raised")
	}

	verified := authnHostEvidence{}
	verified.freezeCredential(definitions.AuthResultOK)
	verified.lowerCredential(definitions.AuthResultTempFail)

	if verified.permits(policy.OperationAuthenticate) {
		t.Fatal("a later host failure did not lower the verified credential")
	}
}

// TestAuthnFSMGuardRejectsUnselectedOK proves an ok host result without a selected rule still needs host evidence.
func TestAuthnFSMGuardRejectsUnselectedOK(t *testing.T) {
	harness := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate, authnFSMGuardVerifier{}, testLuaSubject{})
	harness.execution.authResult = definitions.AuthResultOK

	checkpoint := string(policy.StageSubjectAnalysis)
	before := authnFSMGuardViolations(t, policy.OperationAuthenticate, checkpoint)

	result, err := harness.execution.finalize(
		checkpoint,
		mustAuthnDecisionResponse(t, decision.EffectNotApplicable),
		harness.execution.currentResult(),
	)
	if err != nil {
		t.Fatalf("finalize() error = %v", err)
	}

	if result.auth == nil || result.auth.Decision != AuthDecisionTempFail ||
		result.auth.TerminalState != policyfsm.StateAuthTempFail {
		t.Fatalf("unselected ok without host evidence = %#v, want tempfail", result.auth)
	}

	if got := authnFSMGuardViolations(t, policy.OperationAuthenticate, checkpoint) - before; got != 1 {
		t.Fatalf("guard violations counted = %v, want 1", got)
	}
}

// TestAuthnPermitBackedFollowsFrozenHostEvidence proves the Decision Service effect veto reads the same frozen host
// evidence the auth FSM guard enforces.
func TestAuthnPermitBackedFollowsFrozenHostEvidence(t *testing.T) {
	tests := []struct {
		verifier PasswordVerifier
		name     string
		action   policy.Operation
		want     bool
	}{
		{name: "verified credential backs a permit", verifier: authnFSMGuardVerifier{authenticated: true, userFound: true},
			action: policy.OperationAuthenticate, want: true},
		{name: "failed credential does not back a permit", verifier: authnFSMGuardVerifier{userFound: true},
			action: policy.OperationAuthenticate},
		{name: "another target action is never backed", verifier: authnFSMGuardVerifier{authenticated: true, userFound: true},
			action: policy.OperationListAccounts},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate, test.verifier, testLuaSubject{})
			harness.runBackend(t)
			harness.completeSubject()

			target, err := decision.NewTarget(policy.AuthnNamespace, string(test.action))
			if err != nil {
				t.Fatalf("NewTarget() error = %v", err)
			}

			if got := harness.execution.AuthnPermitBacked(context.Background(), target, string(policy.StageAuthDecision)); got != test.want {
				t.Fatalf("AuthnPermitBacked() = %t, want %t", got, test.want)
			}
		})
	}
}
