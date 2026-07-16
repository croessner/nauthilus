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
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"

	"github.com/gin-gonic/gin"
)

const (
	positiveCacheEnvironmentAttribute = "auth.plugin.environment.cache_test.changed"
	positiveCacheHeaderAttribute      = "request.header.cache_test"
	positiveCacheMetadataAttribute    = "request.metadata.cache_test"
)

type positiveCacheEnvironmentBridge struct {
	calls   atomic.Int32
	changed atomic.Bool
}

// Evaluate records one request-local environment fact without terminating pre-auth.
func (b *positiveCacheEnvironmentBridge) Evaluate(ctx *gin.Context, view *StateView) (bool, bool, bool, error) {
	b.calls.Add(1)

	auth := view.Auth()
	check := auth.beginPolicyCheck(ctx, policycollection.CheckSelector{
		CheckType: policy.CheckTypePluginEnvironment,
		Stage:     policy.StagePreAuth,
		ConfigRef: testPluginEnvironmentConfigRef,
	})
	auth.finishPolicyCheck(check, policyCheckResult{
		Status:  policy.CheckStatusOK,
		Matched: false,
		Attributes: []policycollection.AttributeValue{
			policycollection.BoolAttribute(
				positiveCacheEnvironmentAttribute,
				policy.StagePreAuth,
				auth.policyOperation(),
				b.changed.Load(),
				nil,
			),
		},
	})

	return false, false, true, nil
}

type positiveCacheDefaultSubject struct {
	calls    atomic.Int32
	rejected atomic.Bool
}

type positiveCachePreAuthBoundaryRecorder struct {
	mu                    sync.Mutex
	selected              int
	authenticatedAtSelect []bool
	cacheHitAtSelect      []bool
	deny                  atomic.Bool
}

// Evaluate records scheduler-selected pre-auth execution and the authentication state at that boundary.
func (r *positiveCachePreAuthBoundaryRecorder) Evaluate(ctx *gin.Context, view *StateView) (bool, bool, bool, error) {
	auth := view.Auth()
	selector := policycollection.CheckSelector{
		CheckType: policy.CheckTypePluginEnvironment,
		Stage:     policy.StagePreAuth,
		ConfigRef: testPluginEnvironmentConfigRef,
		Name:      "plugin_environment_positive_cache_boundary",
	}

	if !auth.policyCheckScheduled(ctx, selector) {
		return false, false, false, nil
	}

	r.mu.Lock()
	r.selected++
	r.authenticatedAtSelect = append(r.authenticatedAtSelect, auth.Runtime.Authenticated)
	r.cacheHitAtSelect = append(r.cacheHitAtSelect, ctx.GetBool(definitions.CtxLocalCacheAuthKey))
	r.mu.Unlock()

	denied := r.deny.Load()
	check := auth.beginPolicyCheck(ctx, selector)
	auth.finishPolicyCheck(check, policyCheckResult{
		Status:       policy.CheckStatusOK,
		Matched:      denied,
		DecisionHint: policyDecision(denied, policy.DecisionDeny),
		Attributes: []policycollection.AttributeValue{
			policycollection.BoolAttribute(
				positiveCacheEnvironmentAttribute,
				policy.StagePreAuth,
				auth.policyOperation(),
				denied,
				nil,
			),
		},
	})

	return denied, false, true, nil
}

// snapshot returns an owned view of the recorded selection boundary.
func (r *positiveCachePreAuthBoundaryRecorder) snapshot() (int, []bool, []bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.selected, append([]bool(nil), r.authenticatedAtSelect...), append([]bool(nil), r.cacheHitAtSelect...)
}

// Analyze emits a built-in Lua-subject fact whose value can change per request.
func (s *positiveCacheDefaultSubject) Analyze(ctx *gin.Context, view *StateView, _ *PassDBResult) definitions.AuthResult {
	s.calls.Add(1)
	rejected := s.rejected.Load()
	view.Auth().Runtime.Authorized = !rejected

	if recorder := view.Auth().PolicyScriptRecorder(ctx); recorder != nil {
		recorder.RecordScriptResult(ctx.Request.Context(), policycollection.ScriptResult{
			Kind:          policycollection.ScriptKindSubject,
			Name:          "cache_test",
			Action:        rejected,
			StatusMessage: "warm subject rejected",
		})
	}

	if rejected {
		return definitions.AuthResultFail
	}

	return definitions.AuthResultOK
}

// runPositiveCacheReproducerRequest drives preprocessing and the complete auth FSM.
func runPositiveCacheReproducerRequest(
	t *testing.T,
	cfg *config.FileSettings,
	cache *PositiveBackendAuthenticationCache,
	guid string,
	configure func(*AuthState, *gin.Context),
) (*AuthState, *gin.Context) {
	t.Helper()

	auth, ctx := newRequestOwnedContractAuth(t, cfg, "positive-cache@example.test", "positive-secret", guid)
	auth.deps.BackendAuthenticationCache = cache

	if configure != nil {
		configure(auth, ctx)
	}

	if rejected := auth.PreproccessAuthRequest(ctx); rejected {
		t.Fatalf("%s request was rejected during preprocessing", guid)
	}

	auth.runAuthPipelineFSM(ctx)

	return auth, ctx
}

// activatePositiveCacheSnapshot replaces the active snapshot without installing nested cleanup.
func activatePositiveCacheSnapshot(t *testing.T, snapshot *policyruntime.Snapshot) {
	t.Helper()

	if err := policyruntime.DefaultStore().Activate(snapshot); err != nil {
		t.Fatalf("activate replacement policy snapshot: %v", err)
	}
}

// positiveCacheConfiguredSnapshot returns one authoritative unconditional final decision.
func positiveCacheConfiguredSnapshot(generation uint64, decision policy.Decision) *policyruntime.Snapshot {
	snapshot := customEnforceAuthSnapshotForTest()
	snapshot.Generation = generation
	compiled := snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision]
	compiled.Policies[0].Root = policyruntime.CompiledExpr{Kind: policyruntime.ExprKindAlways}
	compiled.Policies[0].Then.Decision = decision

	if decision == policy.DecisionPermit {
		compiled.Policies[0].Then.FSMEventMarker = policy.FSMEventMarkerAuthPermit
		compiled.Policies[0].Then.ResponseMarker = policy.ResponseMarkerOK
		compiled.Policies[0].Then.ResponseMessage = policyruntime.ResponseMessagePlan{}
		compiled.Policies[0].Then.Obligations = []policyruntime.EffectRequest{
			{ID: policyAuthorityPluginEffectID},
			{ID: policy.ObligationLuaPostActionEnqueue},
		}
	} else {
		compiled.Policies[0].Then.FSMEventMarker = policy.FSMEventMarkerAuthDeny
		compiled.Policies[0].Then.ResponseMarker = policy.ResponseMarkerFail
		compiled.Policies[0].Then.ResponseMessage = policyruntime.ResponseMessagePlan{
			Source:  policy.ResponseSourceLiteral,
			Literal: "policy reloaded deny",
		}
	}

	snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision] = compiled

	return snapshot
}

// positiveCacheInputSnapshot denies when the selected per-request input is true.
func positiveCacheInputSnapshot(attributeID string) *policyruntime.Snapshot {
	snapshot := customEnforceAuthSnapshotForTest()
	compiled := snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision]
	compiled.Policies[0].Root = policyruntime.CompiledExpr{
		Kind:        policyruntime.ExprKindAttribute,
		AttributeID: attributeID,
		Operator:    "is",
		Expected:    policyruntime.TypedValue{Value: true},
		ValueType:   registry.AttributeTypeBool,
	}
	compiled.Policies[0].Then.Decision = policy.DecisionDeny
	compiled.Policies[0].Then.FSMEventMarker = policy.FSMEventMarkerAuthDeny
	compiled.Policies[0].Then.ResponseMarker = policy.ResponseMarkerFail
	compiled.Policies[0].Then.ResponseMessage = policyruntime.ResponseMessagePlan{
		Source:  policy.ResponseSourceLiteral,
		Literal: "warm input denied",
	}
	fallback := compiled.Policies[0]
	fallback.Name = "positive_cache_input_fallback_permit"
	fallback.Root = policyruntime.CompiledExpr{Kind: policyruntime.ExprKindAlways}
	fallback.Then.Decision = policy.DecisionPermit
	fallback.Then.FSMEventMarker = policy.FSMEventMarkerAuthPermit
	fallback.Then.ResponseMarker = policy.ResponseMarkerOK
	fallback.Then.ResponseMessage = policyruntime.ResponseMessagePlan{}
	compiled.Policies = append(compiled.Policies, fallback)
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision] = compiled
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth] = policyruntime.CompiledStagePlan{
		Stage: policy.StagePreAuth,
		Checks: []policyruntime.CompiledCheck{
			{
				Name:       "plugin_environment_cache_test",
				Type:       policy.CheckTypePluginEnvironment,
				ConfigRef:  testPluginEnvironmentConfigRef,
				Stage:      policy.StagePreAuth,
				Operations: []policy.Operation{policy.OperationAuthenticate},
				RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
			},
		},
	}

	return snapshot
}

// positiveCacheRequestInputSnapshot denies when either allowlisted request input equals deny.
func positiveCacheRequestInputSnapshot() *policyruntime.Snapshot {
	snapshot := customEnforceAuthSnapshotForTest()
	compiled := snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision]
	compiled.Policies[0].Root = policyruntime.CompiledExpr{
		Kind: policyruntime.ExprKindAny,
		Children: []policyruntime.CompiledExpr{
			{
				Kind:        policyruntime.ExprKindAttribute,
				AttributeID: positiveCacheHeaderAttribute,
				Operator:    "eq",
				Expected:    policyruntime.TypedValue{Value: "deny"},
				ValueType:   registry.AttributeTypeString,
			},
			{
				Kind:        policyruntime.ExprKindAttribute,
				AttributeID: positiveCacheMetadataAttribute,
				Operator:    "eq",
				Expected:    policyruntime.TypedValue{Value: "deny"},
				ValueType:   registry.AttributeTypeString,
			},
		},
	}
	compiled.Policies[0].Then.Decision = policy.DecisionDeny
	compiled.Policies[0].Then.FSMEventMarker = policy.FSMEventMarkerAuthDeny
	compiled.Policies[0].Then.ResponseMarker = policy.ResponseMarkerFail
	compiled.Policies[0].Then.ResponseMessage = policyruntime.ResponseMessagePlan{
		Source:  policy.ResponseSourceLiteral,
		Literal: "warm request input denied",
	}
	fallback := compiled.Policies[0]
	fallback.Name = "positive_cache_request_input_fallback_permit"
	fallback.Root = policyruntime.CompiledExpr{Kind: policyruntime.ExprKindAlways}
	fallback.Then.Decision = policy.DecisionPermit
	fallback.Then.FSMEventMarker = policy.FSMEventMarkerAuthPermit
	fallback.Then.ResponseMarker = policy.ResponseMarkerOK
	fallback.Then.ResponseMessage = policyruntime.ResponseMessagePlan{}
	compiled.Policies = append(compiled.Policies, fallback)
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision] = compiled
	snapshot.RequestAttributes = policyruntime.RequestAttributeSettings{
		Headers: []policyruntime.RequestHeaderAttribute{
			{Header: "X-Cache-Test", Attribute: positiveCacheHeaderAttribute},
		},
		Metadata: []policyruntime.RequestMetadataAttribute{
			{Key: "x-cache-test", Attribute: positiveCacheMetadataAttribute},
		},
	}

	return snapshot
}

// positiveCachePreAuthBoundarySnapshot configures brute-force and plugin checks at the real pre-auth stage.
func positiveCachePreAuthBoundarySnapshot(generation uint64, runIf string, denyPolicy bool) *policyruntime.Snapshot {
	snapshot := positiveCacheConfiguredSnapshot(generation, policy.DecisionPermit)
	stage := policyruntime.CompiledStagePlan{
		Stage: policy.StagePreAuth,
		Checks: []policyruntime.CompiledCheck{
			{
				Name:       definitions.ControlBruteForce,
				Type:       policy.CheckTypeBruteForce,
				ConfigRef:  policyConfigRefBruteForce,
				Stage:      policy.StagePreAuth,
				Operations: []policy.Operation{policy.OperationAuthenticate},
				RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
			},
			{
				Name:       "plugin_environment_positive_cache_boundary",
				Type:       policy.CheckTypePluginEnvironment,
				ConfigRef:  testPluginEnvironmentConfigRef,
				Stage:      policy.StagePreAuth,
				Operations: []policy.Operation{policy.OperationAuthenticate},
				RunIf:      policyruntime.RunIfPlan{AuthState: runIf},
			},
		},
	}

	if denyPolicy {
		stage.Policies = []policyruntime.CompiledPolicy{
			{
				Name:          "positive_cache_boundary_deny",
				Stage:         policy.StagePreAuth,
				Operations:    []policy.Operation{policy.OperationAuthenticate},
				RequireChecks: []string{"plugin_environment_positive_cache_boundary"},
				Root: policyruntime.CompiledExpr{
					Kind:        policyruntime.ExprKindAttribute,
					AttributeID: positiveCacheEnvironmentAttribute,
					Operator:    "is",
					Expected:    policyruntime.TypedValue{Value: true},
					ValueType:   registry.AttributeTypeBool,
				},
				Then: policyruntime.DecisionPlan{
					Decision:       policy.DecisionDeny,
					FSMEventMarker: policy.FSMEventMarkerPreAuthDeny,
					ResponseMarker: policy.ResponseMarkerFail,
					ResponseMessage: policyruntime.ResponseMessagePlan{
						Source:  policy.ResponseSourceLiteral,
						Literal: "warm pre-auth denied",
					},
				},
			},
		}
	}

	snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth] = stage

	return snapshot
}

// runPositiveCachePreAuthBoundaryRequest records preprocessing state before the normal auth FSM runs.
func runPositiveCachePreAuthBoundaryRequest(
	t *testing.T,
	cfg *config.FileSettings,
	cache *PositiveBackendAuthenticationCache,
	guid string,
) (*AuthState, *gin.Context, bool) {
	t.Helper()

	auth, ctx := newRequestOwnedContractAuth(t, cfg, "positive-cache@example.test", "positive-secret", guid)
	auth.deps.BackendAuthenticationCache = cache

	if rejected := auth.PreproccessAuthRequest(ctx); rejected {
		t.Fatalf("%s request was rejected during preprocessing", guid)
	}

	hitBeforePreAuth := ctx.GetBool(definitions.CtxLocalCacheAuthKey)
	auth.runAuthPipelineFSM(ctx)

	return auth, ctx, hitBeforePreAuth
}

// positiveCacheBruteForceCheckRecorded reports whether the real brute-force check completed for this request.
func positiveCacheBruteForceCheckRecorded(ctx *gin.Context) bool {
	decisionContext, ok := policyDecisionContext(ctx)
	if !ok {
		return false
	}

	check, ok := decisionContext.Report().Checks[definitions.ControlBruteForce]

	return ok && check.Status == policy.CheckStatusOK
}

// assertPositiveCachePreAuthBoundary verifies equal cold/warm selection before cache consumption.
func assertPositiveCachePreAuthBoundary(
	t *testing.T,
	recorder *positiveCachePreAuthBoundaryRecorder,
	coldCtx, warmCtx *gin.Context,
	coldHitBeforePreAuth, warmHitBeforePreAuth bool,
) {
	t.Helper()

	if coldHitBeforePreAuth || warmHitBeforePreAuth {
		t.Errorf("cache hit before pre-auth: cold=%t warm=%t, want false/false", coldHitBeforePreAuth, warmHitBeforePreAuth)
	}

	selected, authenticatedAtSelect, cacheHitAtSelect := recorder.snapshot()
	if selected != 2 || !reflect.DeepEqual(authenticatedAtSelect, []bool{false, false}) {
		t.Errorf("pre-auth selection count/state = %d/%v, want 2/[false false]", selected, authenticatedAtSelect)
	}

	if !reflect.DeepEqual(cacheHitAtSelect, []bool{false, false}) {
		t.Errorf("cache hit markers at pre-auth selection = %v, want [false false]", cacheHitAtSelect)
	}

	bruteForceChecks := 0

	for _, requestCtx := range []*gin.Context{coldCtx, warmCtx} {
		if positiveCacheBruteForceCheckRecorded(requestCtx) {
			bruteForceChecks++
		}
	}

	if bruteForceChecks != 2 {
		t.Errorf("brute-force checks = %d, want 2", bruteForceChecks)
	}
}

// assertPositiveCacheNamedCounts verifies independently named workflow counters.
func assertPositiveCacheNamedCounts(t *testing.T, got, want map[string]int32) {
	t.Helper()

	for name, expected := range want {
		if got[name] != expected {
			t.Errorf("%s calls = %d, want %d", name, got[name], expected)
		}
	}
}

// assertPositiveCacheWarmDenyOutcome verifies that pre-auth denial stops all warm downstream work.
func assertPositiveCacheWarmDenyOutcome(
	t *testing.T,
	cold, warm *AuthState,
	warmCtx *gin.Context,
	verifierCalls, subjectCalls *atomic.Int32,
	policyBridge *backendAuthenticationPolicyBridge,
) {
	t.Helper()

	assertPositiveCacheNamedCounts(t, map[string]int32{
		"backend": verifierCalls.Load(), "subject": subjectCalls.Load(),
		"final policy": policyBridge.effectCalls.Load(), "post": policyBridge.postCalls.Load(),
	}, map[string]int32{"backend": 1, "subject": 1, "final policy": 1, "post": 1})

	if cold.Runtime.AuthFSMTerminalState != string(authFSMStateAuthOK) {
		t.Errorf("cold terminal state = %q, want %q", cold.Runtime.AuthFSMTerminalState, authFSMStateAuthOK)
	}

	if warm.Runtime.AuthFSMTerminalState != string(authFSMStateAuthFail) {
		t.Errorf("warm terminal state = %q, want %q", warm.Runtime.AuthFSMTerminalState, authFSMStateAuthFail)
	}

	if warmCtx.GetBool(definitions.CtxLocalCacheAuthKey) || warm.Runtime.Authenticated {
		t.Errorf("warm denied request consumed snapshot: hit=%t authenticated=%t", warmCtx.GetBool(definitions.CtxLocalCacheAuthKey), warm.Runtime.Authenticated)
	}
}

func TestPositiveBackendAuthenticationCacheWarmPreservesUnauthenticatedPreAuthSelection(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	cfg.Server.Redis.AccountLocalCache.Enabled = true
	cfg.BruteForce = &config.BruteForceSection{}

	activatePolicySnapshotForTest(t, positiveCachePreAuthBoundarySnapshot(507, policy.RunIfUnauthenticated, false))

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	policyBridge := &backendAuthenticationPolicyBridge{}

	restore := installPositiveBackendAuthenticationServices(t, verifierCalls, subjectCalls, policyBridge)
	defer restore()

	recorder := &positiveCachePreAuthBoundaryRecorder{}
	previousEnvironment := regPluginEnv

	RegisterPluginEnvironmentSourceBridge(recorder)
	defer RegisterPluginEnvironmentSourceBridge(previousEnvironment)

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	cold, coldCtx, coldHitBeforePreAuth := runPositiveCachePreAuthBoundaryRequest(t, cfg, cache, "preauth-selection-cold")
	warm, warmCtx, warmHitBeforePreAuth := runPositiveCachePreAuthBoundaryRequest(t, cfg, cache, "preauth-selection-warm")

	assertPositiveCachePreAuthBoundary(t, recorder, coldCtx, warmCtx, coldHitBeforePreAuth, warmHitBeforePreAuth)
	assertPositiveCacheNamedCounts(t, map[string]int32{
		"backend":      verifierCalls.Load(),
		"subject":      subjectCalls.Load(),
		"final policy": policyBridge.effectCalls.Load(),
		"post":         policyBridge.postCalls.Load(),
	}, map[string]int32{"backend": 1, "subject": 2, "final policy": 2, "post": 2})

	if cold.Runtime.AuthFSMTerminalState != string(authFSMStateAuthOK) || warm.Runtime.AuthFSMTerminalState != string(authFSMStateAuthOK) {
		t.Errorf("terminal states cold=%q warm=%q, want auth_ok/auth_ok", cold.Runtime.AuthFSMTerminalState, warm.Runtime.AuthFSMTerminalState)
	}

	if !warmCtx.GetBool(definitions.CtxLocalCacheAuthKey) {
		t.Error("warm request did not consume the backend snapshot after pre-auth")
	}
}

func TestPositiveBackendAuthenticationCacheWarmBruteForceDenyPreventsSnapshotApplication(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	cfg.Server.Redis.AccountLocalCache.Enabled = true
	cfg.BruteForce = &config.BruteForceSection{}

	activatePolicySnapshotForTest(t, positiveCachePreAuthBoundarySnapshot(508, policy.RunIfAny, true))

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	policyBridge := &backendAuthenticationPolicyBridge{}

	restore := installPositiveBackendAuthenticationServices(t, verifierCalls, subjectCalls, policyBridge)
	defer restore()

	recorder := &positiveCachePreAuthBoundaryRecorder{}
	previousEnvironment := regPluginEnv

	RegisterPluginEnvironmentSourceBridge(recorder)
	defer RegisterPluginEnvironmentSourceBridge(previousEnvironment)

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	cold, coldCtx, coldHitBeforePreAuth := runPositiveCachePreAuthBoundaryRequest(t, cfg, cache, "preauth-deny-cold")

	recorder.deny.Store(true)

	warm, warmCtx, warmHitBeforePreAuth := runPositiveCachePreAuthBoundaryRequest(t, cfg, cache, "preauth-deny-warm")

	assertPositiveCachePreAuthBoundary(t, recorder, coldCtx, warmCtx, coldHitBeforePreAuth, warmHitBeforePreAuth)
	assertPositiveCacheWarmDenyOutcome(t, cold, warm, warmCtx, verifierCalls, subjectCalls, policyBridge)
}

func TestPositiveBackendAuthenticationCacheWarmReevaluatesConfiguredPolicyReload(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	activatePolicySnapshotForTest(t, positiveCacheConfiguredSnapshot(501, policy.DecisionPermit))

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	bridge := &backendAuthenticationPolicyBridge{}
	restore := installPositiveBackendAuthenticationServices(t, verifierCalls, subjectCalls, bridge)

	defer restore()

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	cold, _ := runPositiveCacheReproducerRequest(t, cfg, cache, "policy-reload-cold", nil)
	activatePositiveCacheSnapshot(t, positiveCacheConfiguredSnapshot(502, policy.DecisionDeny))
	warm, _ := runPositiveCacheReproducerRequest(t, cfg, cache, "policy-reload-warm", nil)

	if cold.Runtime.AuthFSMTerminalState != string(authFSMStateAuthOK) {
		t.Fatalf("cold terminal state = %q, want %q", cold.Runtime.AuthFSMTerminalState, authFSMStateAuthOK)
	}

	if warm.Runtime.AuthFSMTerminalState != string(authFSMStateAuthFail) || warm.Runtime.StatusMessage != "policy reloaded deny" {
		t.Fatalf("warm terminal=%q status=%q, want deny from generation 502", warm.Runtime.AuthFSMTerminalState, warm.Runtime.StatusMessage)
	}
}

func TestPositiveBackendAuthenticationCacheWarmReevaluatesBuiltInDefaultPolicyInput(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{Generation: 503, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet})

	verifierCalls := &atomic.Int32{}
	subject := &positiveCacheDefaultSubject{}
	previousVerifier := getPasswordVerifier()
	previousSubject := getLuaSubject()
	previousPost := getPostAction()

	RegisterPasswordVerifier(backendAuthenticationContractVerifier{calls: verifierCalls})
	RegisterLuaSubject(subject)
	RegisterPostAction(recordingPlanPostAction{})

	defer func() {
		RegisterPasswordVerifier(previousVerifier)
		RegisterLuaSubject(previousSubject)
		RegisterPostAction(previousPost)
	}()

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	cold, _ := runPositiveCacheReproducerRequest(t, cfg, cache, "default-input-cold", nil)

	subject.rejected.Store(true)

	warm, _ := runPositiveCacheReproducerRequest(t, cfg, cache, "default-input-warm", nil)

	if cold.Runtime.AuthFSMTerminalState != string(authFSMStateAuthOK) {
		t.Fatalf("cold terminal state = %q, want %q", cold.Runtime.AuthFSMTerminalState, authFSMStateAuthOK)
	}

	if warm.Runtime.AuthFSMTerminalState != string(authFSMStateAuthFail) || subject.calls.Load() != 2 {
		t.Fatalf("warm terminal=%q subject calls=%d, want built-in deny and 2", warm.Runtime.AuthFSMTerminalState, subject.calls.Load())
	}
}

func TestPositiveBackendAuthenticationCacheWarmReevaluatesHeaderAndMetadata(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	activatePolicySnapshotForTest(t, positiveCacheRequestInputSnapshot())

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	bridge := &backendAuthenticationPolicyBridge{}
	restore := installPositiveBackendAuthenticationServices(t, verifierCalls, subjectCalls, bridge)

	defer restore()

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	cold, _ := runPositiveCacheReproducerRequest(t, cfg, cache, "request-input-cold", func(auth *AuthState, ctx *gin.Context) {
		ctx.Request.Header.Set("X-Cache-Test", "allow")
		auth.Request.RequestMetadata = map[string][]string{"x-cache-test": {"allow"}}
	})
	warm, _ := runPositiveCacheReproducerRequest(t, cfg, cache, "request-input-warm", func(auth *AuthState, ctx *gin.Context) {
		ctx.Request.Header.Set("X-Cache-Test", "deny")
		auth.Request.RequestMetadata = map[string][]string{"x-cache-test": {"deny"}}
	})

	if cold.Runtime.AuthFSMTerminalState != string(authFSMStateAuthOK) {
		t.Fatalf("cold terminal state = %q, want %q", cold.Runtime.AuthFSMTerminalState, authFSMStateAuthOK)
	}

	if warm.Runtime.AuthFSMTerminalState != string(authFSMStateAuthFail) || warm.Runtime.StatusMessage != "warm request input denied" {
		t.Fatalf("warm terminal=%q status=%q, want request-input deny", warm.Runtime.AuthFSMTerminalState, warm.Runtime.StatusMessage)
	}
}

func TestPositiveBackendAuthenticationCacheWarmReevaluatesEnvironmentFact(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	activatePolicySnapshotForTest(t, positiveCacheInputSnapshot(positiveCacheEnvironmentAttribute))

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	policyBridge := &backendAuthenticationPolicyBridge{}

	restore := installPositiveBackendAuthenticationServices(t, verifierCalls, subjectCalls, policyBridge)
	defer restore()

	environment := &positiveCacheEnvironmentBridge{}
	previousEnvironment := regPluginEnv

	RegisterPluginEnvironmentSourceBridge(environment)
	defer RegisterPluginEnvironmentSourceBridge(previousEnvironment)

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	cold, _ := runPositiveCacheReproducerRequest(t, cfg, cache, "environment-cold", nil)

	environment.changed.Store(true)

	warm, _ := runPositiveCacheReproducerRequest(t, cfg, cache, "environment-warm", nil)

	if cold.Runtime.AuthFSMTerminalState != string(authFSMStateAuthOK) {
		t.Fatalf("cold terminal state = %q, want %q", cold.Runtime.AuthFSMTerminalState, authFSMStateAuthOK)
	}

	if warm.Runtime.AuthFSMTerminalState != string(authFSMStateAuthFail) || environment.calls.Load() != 2 {
		t.Fatalf("warm terminal=%q environment calls=%d, want input deny and 2", warm.Runtime.AuthFSMTerminalState, environment.calls.Load())
	}
}

func TestPositiveBackendAuthenticationCacheColdWarmCounts(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true
	snapshot := positiveCacheConfiguredSnapshot(504, policy.DecisionPermit)
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth] = positiveCacheInputSnapshot(positiveCacheEnvironmentAttribute).StagePlans[policy.OperationAuthenticate][policy.StagePreAuth]
	activatePolicySnapshotForTest(t, snapshot)

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	policyBridge := &backendAuthenticationPolicyBridge{}
	restore := installPositiveBackendAuthenticationServices(t, verifierCalls, subjectCalls, policyBridge)

	defer restore()

	environment := &positiveCacheEnvironmentBridge{}
	previousEnvironment := regPluginEnv

	RegisterPluginEnvironmentSourceBridge(environment)
	defer RegisterPluginEnvironmentSourceBridge(previousEnvironment)

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	runPositiveCacheReproducerRequest(t, cfg, cache, "counts-cold", nil)
	runPositiveCacheReproducerRequest(t, cfg, cache, "counts-warm", nil)

	got := map[string]int32{
		"backend":      verifierCalls.Load(),
		"environment":  environment.calls.Load(),
		"subject":      subjectCalls.Load(),
		"final policy": policyBridge.effectCalls.Load(),
		"post":         policyBridge.postCalls.Load(),
	}
	want := map[string]int32{"backend": 1, "environment": 2, "subject": 2, "final policy": 2, "post": 2}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cold/warm calls = %#v, want %#v", got, want)
	}
}

func TestPositiveBackendAuthenticationCacheSnapshotParity(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	activatePolicySnapshotForTest(t, positiveCacheConfiguredSnapshot(505, policy.DecisionPermit))

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	bridge := &backendAuthenticationPolicyBridge{}

	restore := installPositiveBackendAuthenticationServices(t, verifierCalls, subjectCalls, bridge)
	defer restore()

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	cold, _ := runPositiveCacheReproducerRequest(t, cfg, cache, "snapshot-cold", nil)
	warm, _ := runPositiveCacheReproducerRequest(t, cfg, cache, "snapshot-warm", nil)
	coldResult := newPassDBResultFromAuthStateForTest(cold)
	warmResult := newPassDBResultFromAuthStateForTest(warm)

	defer PutPassDBResultToPool(coldResult)
	defer PutPassDBResultToPool(warmResult)

	coldSnapshot := snapshotPassDBResult(coldResult)
	warmSnapshot := snapshotPassDBResult(warmResult)

	if !reflect.DeepEqual(warmSnapshot, coldSnapshot) {
		t.Fatalf("warm backend snapshot differs from cold: got %#v want %#v", warmSnapshot, coldSnapshot)
	}

	warmResult.Attributes["uid"][0] = "mutated"
	if reflect.DeepEqual(snapshotPassDBResult(warmResult), snapshotPassDBResult(coldResult)) {
		t.Fatal("warm backend snapshot is not independently owned")
	}
}

type positiveCacheConcurrentWarmFixture struct {
	authStates   []*AuthState
	contexts     []*gin.Context
	coldSnapshot semanticPassDBSnapshot
}

// newPositiveCacheConcurrentWarmFixture creates independently owned equal-key warm requests.
func newPositiveCacheConcurrentWarmFixture(
	t *testing.T,
	cfg *config.FileSettings,
	cache *PositiveBackendAuthenticationCache,
	requestCount int,
) positiveCacheConcurrentWarmFixture {
	t.Helper()

	cold, _ := runPositiveCacheReproducerRequest(t, cfg, cache, "concurrent-warm-cold", nil)
	coldResult := newPassDBResultFromAuthStateForTest(cold)
	fixture := positiveCacheConcurrentWarmFixture{
		authStates:   make([]*AuthState, requestCount),
		contexts:     make([]*gin.Context, requestCount),
		coldSnapshot: snapshotPassDBResult(coldResult),
	}
	PutPassDBResultToPool(coldResult)

	for index := range requestCount {
		fixture.authStates[index], fixture.contexts[index] = newRequestOwnedContractAuth(
			t,
			cfg,
			"positive-cache@example.test",
			"positive-secret",
			fmt.Sprintf("concurrent-warm-%d", index),
		)
		fixture.authStates[index].deps.BackendAuthenticationCache = cache
	}

	return fixture
}

// runPositiveCacheWarmRequest executes one normal warm preprocess and FSM path.
func runPositiveCacheWarmRequest(auth *AuthState, ctx *gin.Context, worker int) error {
	if auth.PreproccessAuthRequest(ctx) {
		return fmt.Errorf("warm request %d rejected during preprocessing", worker)
	}

	if ctx.GetBool(definitions.CtxLocalCacheAuthKey) {
		return fmt.Errorf("warm request %d consumed backend state before pre-auth", worker)
	}

	auth.runAuthPipelineFSM(ctx)

	if !ctx.GetBool(definitions.CtxLocalCacheAuthKey) {
		return fmt.Errorf("warm request %d missed backend cache", worker)
	}

	if auth.Runtime.AuthFSMTerminalState != string(authFSMStateAuthOK) {
		return fmt.Errorf("warm request %d terminal state %q", worker, auth.Runtime.AuthFSMTerminalState)
	}

	return nil
}

// execute runs all prepared warm requests behind one start barrier.
func (f positiveCacheConcurrentWarmFixture) execute() []error {
	start := make(chan struct{})
	errors := make(chan error, len(f.authStates))

	var workers sync.WaitGroup

	for index := range f.authStates {
		workers.Add(1)

		go func(worker int) {
			defer workers.Done()

			<-start

			if err := runPositiveCacheWarmRequest(f.authStates[worker], f.contexts[worker], worker); err != nil {
				errors <- err
			}
		}(index)
	}

	close(start)
	workers.Wait()
	close(errors)

	result := make([]error, 0, len(f.authStates))

	for err := range errors {
		result = append(result, err)
	}

	return result
}

// assertSnapshots verifies complete independent backend results for every warm request.
func (f positiveCacheConcurrentWarmFixture) assertSnapshots(t *testing.T) {
	t.Helper()

	for index, auth := range f.authStates {
		result := newPassDBResultFromAuthStateForTest(auth)
		got := snapshotPassDBResult(result)
		PutPassDBResultToPool(result)

		if !reflect.DeepEqual(got, f.coldSnapshot) {
			t.Errorf("warm request %d backend snapshot differs: got %#v want %#v", index, got, f.coldSnapshot)
		}
	}
}

// assertPositiveCacheConcurrentCounts verifies backend-only reuse across all requests.
func assertPositiveCacheConcurrentCounts(
	t *testing.T,
	requestCount int32,
	verifierCalls, subjectCalls *atomic.Int32,
	environment *positiveCacheEnvironmentBridge,
	policyBridge *backendAuthenticationPolicyBridge,
) {
	t.Helper()

	counts := map[string]struct {
		got  int32
		want int32
	}{
		"backend":      {got: verifierCalls.Load(), want: 1},
		"environment":  {got: environment.calls.Load(), want: requestCount},
		"subject":      {got: subjectCalls.Load(), want: requestCount},
		"final policy": {got: policyBridge.effectCalls.Load(), want: requestCount},
		"post":         {got: policyBridge.postCalls.Load(), want: requestCount},
	}

	for name, count := range counts {
		if count.got != count.want {
			t.Errorf("%s calls = %d, want %d", name, count.got, count.want)
		}
	}
}

func TestPositiveBackendAuthenticationCacheConcurrentWarmRequestsReevaluateAuthority(t *testing.T) {
	const warmRequests = 16

	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true
	snapshot := positiveCacheConfiguredSnapshot(506, policy.DecisionPermit)
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth] = positiveCacheInputSnapshot(positiveCacheEnvironmentAttribute).StagePlans[policy.OperationAuthenticate][policy.StagePreAuth]
	activatePolicySnapshotForTest(t, snapshot)

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	policyBridge := &backendAuthenticationPolicyBridge{}
	restore := installPositiveBackendAuthenticationServices(t, verifierCalls, subjectCalls, policyBridge)

	defer restore()

	environment := &positiveCacheEnvironmentBridge{}
	previousEnvironment := regPluginEnv

	RegisterPluginEnvironmentSourceBridge(environment)
	defer RegisterPluginEnvironmentSourceBridge(previousEnvironment)

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	fixture := newPositiveCacheConcurrentWarmFixture(t, cfg, cache, warmRequests)

	for _, err := range fixture.execute() {
		t.Error(err)
	}

	fixture.assertSnapshots(t)
	assertPositiveCacheConcurrentCounts(t, warmRequests+1, verifierCalls, subjectCalls, environment, policyBridge)
}

var _ PluginEnvironmentSourceBridge = (*positiveCacheEnvironmentBridge)(nil)
var _ LuaSubject = (*positiveCacheDefaultSubject)(nil)
