package pluginruntime

import (
	"context"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
	"github.com/croessner/nauthilus/server/policy/report"
)

const (
	effectObligationName      = "sync_obligation"
	effectPostActionName      = "post_action"
	effectObligationQualified = testRuntimeModuleName + "." + effectObligationName
	effectPostActionQualified = testRuntimeModuleName + "." + effectPostActionName
	effectMessageArg          = "message"
	effectMessageValue        = "hello"
	effectFeatureArg          = "feature"
	effectFeatureValue        = "brute_force"
	effectInputFactAttribute  = "plugin.subject.customer.risk"
	effectResultFactAttribute = "plugin.resource.customer.applied"
	effectPublicLogKey        = "policy_fact_customer_applied"
	effectPublicLogValue      = "yes"
	effectResponseHeaderValue = "true"
	effectStatusText          = "native effect status"
)

func TestEffectBridgeExecutesObligationSynchronously(t *testing.T) {
	target := &fakeObligationTarget{}
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterObligationTarget(target)
	})
	auth := newSubjectTestAuth(t)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{
		ID:   effectObligationQualified,
		Args: map[string]any{effectMessageArg: effectMessageValue},
	})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	if !target.called {
		t.Fatal("obligation returned before Execute was called")
	}

	if value, _ := target.args.Get(effectMessageArg); value != effectMessageValue {
		t.Fatalf("message arg = %#v, want hello", value)
	}
}

func TestEffectBridgePassesPolicyFactsToObligation(t *testing.T) {
	target := &fakeObligationTarget{}
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterObligationTarget(target)
	})
	auth := newSubjectTestAuth(t)
	recordEffectInputFact(t, auth)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{
		ID: effectObligationQualified,
		Args: map[string]any{
			effectMessageArg: effectMessageValue,
			effectFeatureArg: effectFeatureValue,
		},
	})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	assertEffectRequestArgsAndFacts(t, target.args, target.facts)
}

func TestEffectBridgePassesArgsAndFactsToPostAction(t *testing.T) {
	requests := make(chan pluginapi.PostActionRequest, 1)
	target := &fakePostActionTarget{requests: requests}
	host := NewHost()
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterPostActionTarget(target)
	}, WithHost(host))
	auth := newSubjectTestAuth(t)
	recordEffectInputFact(t, auth)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{
		ID: effectPostActionQualified,
		Args: map[string]any{
			effectMessageArg: effectMessageValue,
			effectFeatureArg: effectFeatureValue,
		},
	})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	select {
	case request := <-requests:
		assertEffectRequestArgsAndFacts(t, request.Args, request.Facts)
	case <-time.After(time.Second):
		t.Fatal("post-action target was not invoked")
	}

	host.WaitWorkers()
}

func TestEffectBridgeAppliesObligationStatusLogsAndFacts(t *testing.T) {
	target := &fakeObligationTarget{
		result: pluginapi.ObligationResult{
			Status: &pluginapi.StatusMessage{DefaultText: effectStatusText},
			Logs: []pluginapi.LogField{
				{Key: effectPublicLogKey, Value: effectPublicLogValue},
			},
			Facts: []pluginapi.PolicyFact{
				{Attribute: effectResultFactAttribute, Value: true},
			},
			Applied: true,
		},
	}
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterObligationTarget(target)
	})
	auth := newSubjectTestAuth(t)
	activateEffectResultPolicySnapshot(t, effectResultFactAttribute)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{
		ID: effectObligationQualified,
	})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	if auth.Runtime.StatusMessage != effectStatusText {
		t.Fatalf("status = %q, want %q", auth.Runtime.StatusMessage, effectStatusText)
	}

	if !hasAdditionalLog(auth.Runtime.AdditionalLogs, effectPublicLogKey, effectPublicLogValue) {
		t.Fatalf("additional logs = %#v, want public effect log", auth.Runtime.AdditionalLogs)
	}

	policyReport := auth.PolicyDecisionContext(auth.Request.HTTPClientContext).Report()
	if value := policyReport.Attributes[effectResultFactAttribute].Value; value != true {
		t.Fatalf("obligation result fact = %#v, want true", value)
	}
}

func TestEffectBridgeAppliesObligationResponseMutationHeaders(t *testing.T) {
	target := &fakeObligationTarget{
		result: pluginapi.ObligationResult{
			Response: pluginapi.ResponseMutation{
				Headers: pluginapi.ResponseHeaderMutation{
					Set: map[string][]string{
						responseMutationHeader: {effectResponseHeaderValue},
					},
				},
			},
			Applied: true,
		},
	}
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterObligationTarget(target)
	})
	auth := newSubjectTestAuth(t)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{
		ID: effectObligationQualified,
	})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	if got := auth.Request.HTTPClientContext.Writer.Header().Get(responseMutationHeader); got != effectResponseHeaderValue {
		t.Fatalf("%s = %q, want true", responseMutationHeader, got)
	}
}

func TestEffectBridgeRejectsUnknownObligationResultFact(t *testing.T) {
	target := &fakeObligationTarget{
		result: pluginapi.ObligationResult{
			Facts: []pluginapi.PolicyFact{
				{Attribute: "plugin.resource.customer.unknown", Value: true},
			},
			Applied: true,
		},
	}
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterObligationTarget(target)
	})
	auth := newSubjectTestAuth(t)
	activateEffectResultPolicySnapshot(t)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{
		ID: effectObligationQualified,
	})
	if !handled {
		t.Fatal("ExecutePolicyEffect() handled = false, want true")
	}

	if ok {
		t.Fatal("ExecutePolicyEffect() ok = true, want false for unknown obligation fact")
	}
}

func TestEffectBridgeRejectsWrongStageObligationResultFact(t *testing.T) {
	target := &fakeObligationTarget{
		result: pluginapi.ObligationResult{
			Facts: []pluginapi.PolicyFact{
				{Attribute: effectResultFactAttribute, Value: true},
			},
			Applied: true,
		},
	}
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterObligationTarget(target)
	})
	auth := newSubjectTestAuth(t)
	activatePluginPolicySnapshot(t, pluginPolicySnapshotSpec{
		stage:         policy.StagePreAuth,
		category:      policyregistry.AttributeCategoryResource,
		attributeType: policyregistry.AttributeTypeBool,
	}, effectResultFactAttribute)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{
		ID: effectObligationQualified,
	})
	if !handled {
		t.Fatal("ExecutePolicyEffect() handled = false, want true")
	}

	if ok {
		t.Fatal("ExecutePolicyEffect() ok = true, want false for wrong-stage obligation fact")
	}
}

func TestEffectBridgeMapsObligationErrorToFailure(t *testing.T) {
	target := &fakeObligationTarget{err: context.Canceled}
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterObligationTarget(target)
	})
	auth := newSubjectTestAuth(t)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{ID: effectObligationQualified})
	if !handled {
		t.Fatal("ExecutePolicyEffect() handled = false, want true")
	}

	if ok {
		t.Fatal("ExecutePolicyEffect() ok = true, want false")
	}
}

func TestEffectBridgeEnqueuesPostActionUnderHostSupervision(t *testing.T) {
	target := &fakePostActionTarget{called: make(chan struct{})}
	host := NewHost()
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterPostActionTarget(target)
	}, WithHost(host))
	auth := newSubjectTestAuth(t)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{ID: effectPostActionQualified})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	select {
	case <-target.called:
	case <-time.After(time.Second):
		t.Fatal("post-action target was not invoked")
	}

	host.WaitWorkers()
}

func TestEffectBridgeRecoversPostActionPanic(t *testing.T) {
	observer := &recordingObserver{}
	target := &fakePostActionTarget{called: make(chan struct{}), panicEnqueue: true}
	host := NewHost()
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterPostActionTarget(target)
	}, WithHost(host), WithObserver(observer))
	auth := newSubjectTestAuth(t)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{ID: effectPostActionQualified})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	select {
	case <-target.called:
	case <-time.After(time.Second):
		t.Fatal("post-action target was not invoked")
	}

	host.WaitWorkers()

	if !observer.sawPanic(effectPostActionName, "Enqueue") {
		t.Fatalf("observer records = %#v, want post-action panic", observer.records)
	}
}

func newEffectTestBridge(t *testing.T, register func(pluginapi.Registrar) error, options ...Option) *EffectBridge {
	t.Helper()

	runner := newTestRunner(t, &runtimePlugin{}, register, options...)
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	return NewEffectBridge(runner)
}

type fakeObligationTarget struct {
	result pluginapi.ObligationResult
	facts  []pluginapi.PolicyFact
	args   pluginapi.ArgsView
	err    error
	called bool
}

func (t *fakeObligationTarget) Name() string {
	return effectObligationName
}

func (t *fakeObligationTarget) Execute(_ context.Context, request pluginapi.ObligationRequest) (pluginapi.ObligationResult, error) {
	t.called = true
	t.args = request.Args

	t.facts = append([]pluginapi.PolicyFact(nil), request.Facts...)
	if t.result.Status != nil ||
		len(t.result.Logs) > 0 ||
		len(t.result.Facts) > 0 ||
		obligationResultHasResponseMutation(t.result) ||
		t.result.Temporary {
		return t.result, t.err
	}

	return pluginapi.ObligationResult{Applied: t.err == nil}, t.err
}

type fakePostActionTarget struct {
	requests     chan pluginapi.PostActionRequest
	called       chan struct{}
	panicEnqueue bool
}

func (t *fakePostActionTarget) Name() string {
	return effectPostActionName
}

func (t *fakePostActionTarget) Enqueue(_ context.Context, request pluginapi.PostActionRequest) (pluginapi.PostActionEnqueueResult, error) {
	if t.called != nil {
		close(t.called)
	}

	if t.requests != nil {
		t.requests <- request
	}

	if t.panicEnqueue {
		panic("post-action panic")
	}

	return pluginapi.PostActionEnqueueResult{Enqueued: true}, nil
}

func obligationResultHasResponseMutation(result pluginapi.ObligationResult) bool {
	return result.Response.StatusHeader ||
		len(result.Response.Headers.Set) > 0 ||
		len(result.Response.Headers.Delete) > 0
}

func recordEffectInputFact(t *testing.T, auth *core.AuthState) {
	t.Helper()

	activatePluginPolicySnapshot(t, pluginPolicySnapshotSpec{
		stage:         policy.StageSubjectAnalysis,
		category:      policyregistry.AttributeCategorySubject,
		attributeType: policyregistry.AttributeTypeNumber,
	}, effectInputFactAttribute)

	policyCtx := auth.PolicyDecisionContext(auth.Request.HTTPClientContext)
	policyCtx.RecordAttribute(policycollection.AttributeValue{
		ID:        effectInputFactAttribute,
		Stage:     policy.StageSubjectAnalysis,
		Operation: policy.OperationAuthenticate,
		Value:     float64(0.9),
	})
}

func activateEffectResultPolicySnapshot(t *testing.T, attributes ...string) {
	t.Helper()

	activatePluginPolicySnapshot(t, pluginPolicySnapshotSpec{
		stage:         policy.StageAuthDecision,
		category:      policyregistry.AttributeCategoryResource,
		attributeType: policyregistry.AttributeTypeBool,
	}, attributes...)
}

func assertEffectRequestArgsAndFacts(t *testing.T, args pluginapi.ArgsView, facts []pluginapi.PolicyFact) {
	t.Helper()

	if value, _ := args.Get(effectMessageArg); value != effectMessageValue {
		t.Fatalf("message arg = %#v, want %s", value, effectMessageValue)
	}

	if value, _ := args.Get(effectFeatureArg); value != effectFeatureValue {
		t.Fatalf("feature arg = %#v, want %s", value, effectFeatureValue)
	}

	if len(facts) != 1 || facts[0].Attribute != effectInputFactAttribute || facts[0].Value != float64(0.9) {
		t.Fatalf("effect facts = %#v, want input policy fact", facts)
	}
}

func hasAdditionalLog(logs []any, key string, value any) bool {
	for index := 0; index+1 < len(logs); index += 2 {
		if logs[index] == key && logs[index+1] == value {
			return true
		}
	}

	return false
}
