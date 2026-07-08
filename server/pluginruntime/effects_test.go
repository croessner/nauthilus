package pluginruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/policy"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	"github.com/croessner/nauthilus/v3/server/policy/report"
)

const (
	effectObligationName      = "sync_obligation"
	effectPostActionName      = "post_action"
	effectProducerActionName  = "post_action_producer"
	effectConsumerActionName  = "post_action_consumer"
	effectObligationQualified = testRuntimeModuleName + "." + effectObligationName
	effectPostActionQualified = testRuntimeModuleName + "." + effectPostActionName
	effectProducerQualified   = testRuntimeModuleName + "." + effectProducerActionName
	effectConsumerQualified   = testRuntimeModuleName + "." + effectConsumerActionName
	effectInvalidRuntimeKey   = "post_action_invalid"
	effectSecretRuntimeValue  = "super-secret-runtime-value"
	effectMessageArg          = "message"
	effectMessageValue        = "hello"
	effectFeatureArg          = "feature"
	effectFeatureValue        = "brute_force"
	effectExchangeKey         = "post_action_exchange"
	effectExchangeValue       = "ready"
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

func TestEffectBridgePassesCredentialsToPostAction(t *testing.T) {
	requests := make(chan pluginapi.PostActionRequest, 1)
	target := &fakePostActionTarget{requests: requests}
	host := NewHost()
	module := initialRuntimeModule(nil)
	module.AllowCapabilities = []pluginapi.Capability{pluginapi.CapabilityCredentials}
	runner := newStartedTestRunnerWithModule(t, &runtimePlugin{}, module, func(registrar pluginapi.Registrar) error {
		if err := registrar.RequireCapability(pluginapi.CapabilityCredentials); err != nil {
			return err
		}

		return registrar.RegisterPostActionTarget(target)
	}, WithHost(host))
	bridge := NewEffectBridge(runner)
	auth := newSubjectTestAuth(t)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{ID: effectPostActionQualified})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	select {
	case request := <-requests:
		if request.PasswordHash == "" {
			t.Fatal("post-action password hash is empty")
		}

		if request.PasswordHash != postActionPasswordHash(auth) {
			t.Fatalf("post-action password hash = %q, want host-owned hash %q", request.PasswordHash, postActionPasswordHash(auth))
		}

		credential, ok := request.Credentials.Password(context.Background())
		if !ok {
			t.Fatal("post-action credential provider did not expose the request password")
		}

		var got string

		if err := credential.WithBytes(func(value []byte) error {
			got = string(value)

			return nil
		}); err != nil {
			t.Fatalf("credential callback error = %v", err)
		}

		if got != backendTestPassword {
			t.Fatalf("post-action password = %q, want %q", got, backendTestPassword)
		}
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

func TestEffectBridgeRunsPostActionPlanInOrderAndSharesRuntimeDelta(t *testing.T) {
	callOrder := make(chan string, 2)
	consumerRequests := make(chan pluginapi.PostActionRequest, 1)
	producer := &fakePostActionTarget{
		name:  effectProducerActionName,
		order: callOrder,
		result: pluginapi.PostActionEnqueueResult{
			RuntimeDelta: pluginapi.RuntimeDelta{
				Set: map[string]any{effectExchangeKey: effectExchangeValue},
			},
			Enqueued: true,
		},
	}
	consumer := &fakePostActionTarget{
		name:     effectConsumerActionName,
		order:    callOrder,
		requests: consumerRequests,
	}
	host := NewHost()
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		if err := registrar.RegisterPostActionTarget(producer); err != nil {
			return err
		}

		return registrar.RegisterPostActionTarget(consumer)
	}, WithHost(host))
	auth := newSubjectTestAuth(t)

	handled, ok := bridge.EnqueuePostActionPlan(auth.Request.HTTPClientContext, auth.View(), []core.PostActionPlanStep{
		core.NewNativePostActionPlanStep(report.EffectRequest{ID: effectProducerQualified}),
		core.NewNativePostActionPlanStep(report.EffectRequest{ID: effectConsumerQualified}),
	})
	if !handled || !ok {
		t.Fatalf("EnqueuePostActionPlan() handled=%t ok=%t, want true/true", handled, ok)
	}

	host.WaitWorkers()

	assertPostActionOrder(t, callOrder, effectProducerActionName, effectConsumerActionName)

	select {
	case request := <-consumerRequests:
		value, ok := request.Runtime.Get(effectExchangeKey)
		if !ok || value != effectExchangeValue {
			t.Fatalf("consumer runtime value = %#v, %t; want %q", value, ok, effectExchangeValue)
		}
	default:
		t.Fatal("consumer post-action was not invoked")
	}
}

func TestEffectBridgeRejectsInvalidPostActionRuntimeDelta(t *testing.T) {
	consumerCalled := make(chan struct{})
	producer := &fakePostActionTarget{
		name: effectProducerActionName,
		result: pluginapi.PostActionEnqueueResult{
			RuntimeDelta: pluginapi.RuntimeDelta{
				Set: map[string]any{effectInvalidRuntimeKey: &secretRuntimeValue{value: effectSecretRuntimeValue}},
			},
			Enqueued: true,
		},
	}
	consumer := &fakePostActionTarget{
		name:   effectConsumerActionName,
		called: consumerCalled,
	}
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		if err := registrar.RegisterPostActionTarget(producer); err != nil {
			return err
		}

		return registrar.RegisterPostActionTarget(consumer)
	})
	auth := newSubjectTestAuth(t)

	plan, err := bridge.newPostActionPlan(auth.Request.HTTPClientContext, auth, []core.PostActionPlanStep{
		core.NewNativePostActionPlanStep(report.EffectRequest{ID: effectProducerQualified}),
		core.NewNativePostActionPlanStep(report.EffectRequest{ID: effectConsumerQualified}),
	})
	if err != nil {
		t.Fatalf("newPostActionPlan() error = %v", err)
	}

	err = bridge.runPostActionPlan(context.Background(), plan)
	if !errors.Is(err, ErrUnsupportedRuntimeValue) {
		t.Fatalf("runPostActionPlan() error = %v, want unsupported runtime value", err)
	}

	if strings.Contains(err.Error(), effectSecretRuntimeValue) {
		t.Fatalf("invalid runtime delta error leaked value: %v", err)
	}

	select {
	case <-consumerCalled:
		t.Fatal("consumer post-action ran after invalid producer runtime delta")
	default:
	}
}

func TestEffectBridgeDetachesPostActionFromCanceledRequestContext(t *testing.T) {
	ctxErrs := make(chan error, 1)
	target := &fakePostActionTarget{ctxErrs: ctxErrs}
	host := NewHost()
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterPostActionTarget(target)
	}, WithHost(host))
	t.Cleanup(host.WaitWorkers)

	auth := newSubjectTestAuth(t)
	reqCtx, cancel := context.WithCancel(context.Background())
	cancel()

	auth.Request.HTTPClientContext.Request = auth.Request.HTTPClientContext.Request.WithContext(reqCtx)
	auth.Request.HTTPClientRequest = auth.Request.HTTPClientContext.Request

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{ID: effectPostActionQualified})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	select {
	case err := <-ctxErrs:
		if err != nil {
			t.Fatalf("post-action context err = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("post-action target was not invoked")
	}
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
	ctxErrs      chan error
	called       chan struct{}
	order        chan string
	result       pluginapi.PostActionEnqueueResult
	name         string
	panicEnqueue bool
}

func (t *fakePostActionTarget) Name() string {
	if t.name != "" {
		return t.name
	}

	return effectPostActionName
}

func (t *fakePostActionTarget) Enqueue(ctx context.Context, request pluginapi.PostActionRequest) (pluginapi.PostActionEnqueueResult, error) {
	if t.called != nil {
		close(t.called)
	}

	if t.order != nil {
		t.order <- t.Name()
	}

	if t.ctxErrs != nil {
		select {
		case <-ctx.Done():
			t.ctxErrs <- ctx.Err()
		case <-time.After(50 * time.Millisecond):
			t.ctxErrs <- ctx.Err()
		}
	}

	if t.requests != nil {
		t.requests <- request
	}

	if t.panicEnqueue {
		panic("post-action panic")
	}

	if postActionResultIsSet(t.result) {
		return t.result, nil
	}

	return pluginapi.PostActionEnqueueResult{Enqueued: true}, nil
}

// postActionResultIsSet distinguishes an explicit test result from the default enqueue success.
func postActionResultIsSet(result pluginapi.PostActionEnqueueResult) bool {
	return result.Status != nil ||
		len(result.Logs) > 0 ||
		len(result.RuntimeDelta.Set) > 0 ||
		len(result.RuntimeDelta.Delete) > 0 ||
		result.QueuedID != "" ||
		result.Enqueued ||
		result.Temporary
}

func obligationResultHasResponseMutation(result pluginapi.ObligationResult) bool {
	return result.Response.StatusHeader ||
		len(result.Response.Headers.Set) > 0 ||
		len(result.Response.Headers.Delete) > 0
}

type secretRuntimeValue struct {
	value string
}

func assertPostActionOrder(t *testing.T, order <-chan string, want ...string) {
	t.Helper()

	for _, expected := range want {
		select {
		case got := <-order:
			if got != expected {
				t.Fatalf("post-action order item = %q, want %q", got, expected)
			}
		default:
			t.Fatalf("missing post-action order item %q", expected)
		}
	}
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
