package pluginruntime

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/pluginapi/v1/exchange"
	pluginpassword "github.com/croessner/nauthilus/v3/pluginapi/v1/password"
	"github.com/croessner/nauthilus/v3/server/core"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/policy"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	"github.com/croessner/nauthilus/v3/server/policy/report"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

var _ core.PluginEffectBridge = (*EffectBridge)(nil)

// EffectBridge adapts policy-selected native plugin effects into core.
type EffectBridge struct {
	runner *Runner
}

// NewEffectBridge returns an effect bridge bound to one plugin runner.
func NewEffectBridge(runner *Runner) *EffectBridge {
	return &EffectBridge{runner: runner}
}

// IsPostActionEffect reports whether a policy effect resolves to a native post-action target.
func (b *EffectBridge) IsPostActionEffect(effect report.EffectRequest) bool {
	if b == nil || b.runner == nil || b.runner.registry == nil || effect.ID == "" {
		return false
	}

	component, ok := b.runner.registry.Lookup(effect.ID)

	return ok && component.Kind == pluginregistry.ComponentKindPostActionTarget
}

// ExecutePolicyEffect dispatches one policy-selected native plugin effect.
func (b *EffectBridge) ExecutePolicyEffect(ctx *gin.Context, view *core.StateView, effect report.EffectRequest) (bool, bool) {
	auth := authFromView(view)
	if b == nil || b.runner == nil || auth == nil || effect.ID == "" {
		return false, false
	}

	component, ok := b.runner.registry.Lookup(effect.ID)
	if !ok {
		return false, false
	}

	switch component.Kind {
	case pluginregistry.ComponentKindObligationTarget:
		return true, b.executeObligation(ctx, auth, effect)
	case pluginregistry.ComponentKindPostActionTarget:
		return b.EnqueuePostActionPlan(ctx, view, []core.PostActionPlanStep{core.NewNativePostActionPlanStep(effect)})
	default:
		return false, false
	}
}

func (b *EffectBridge) executeObligation(ctx *gin.Context, auth *core.AuthState, effect report.EffectRequest) bool {
	policyCtx := auth.PolicyDecisionContext(ctx)

	request, err := newPluginEffectRequest(auth, policyCtx, effect.Args)
	if err != nil {
		return false
	}

	result, err := b.runner.ExecuteObligation(contextFromGin(ctx), effect.ID, pluginapi.ObligationRequest{
		Snapshot: request.snapshot,
		Runtime:  request.runtime,
		Args:     request.args,
		Facts:    request.facts,
	})
	if err != nil {
		return false
	}

	if err := applyPluginEffectFacts(policyCtx, result.Facts); err != nil {
		return false
	}

	applyPluginStatus(auth, result.Status)
	applySubjectLogs(auth, result.Logs)
	auth.ApplyPluginResponseMutation(ctx, result.Response)
	applyEffectRuntimeDelta(auth, result.RuntimeDelta)

	return result.Applied || !result.Temporary
}

// EnqueuePostActionPlan starts one detached worker for ordered post-action steps.
func (b *EffectBridge) EnqueuePostActionPlan(
	ctx *gin.Context,
	view *core.StateView,
	steps []core.PostActionPlanStep,
) (bool, bool) {
	auth := authFromView(view)
	if b == nil || b.runner == nil || b.runner.host == nil || auth == nil || len(steps) == 0 {
		return false, false
	}

	plan, err := b.newPostActionPlan(ctx, auth, steps)
	if err != nil {
		core.ReleasePostActionPlanSteps(steps)

		return true, false
	}

	b.runner.host.Go(plan.requestContext, postActionPlanWorkerName, func(workerCtx context.Context) error {
		return b.runPostActionPlan(workerCtx, plan)
	})

	return true, true
}

const postActionPlanWorkerName = "post_action_plan"

const (
	policyAttributeLuaEnvironmentBlocklistTriggered = "auth.lua.environment.blocklist.triggered"
	policyDetailClientNet                           = "client_net"
)

type postActionPlan struct {
	requestContext context.Context
	executionDone  <-chan struct{}
	runtimeValues  map[string]any
	sourceSteps    []core.PostActionPlanStep
	steps          []postActionPlanStep
	facts          []pluginapi.PolicyFact
	snapshot       pluginapi.RequestSnapshot
	passwordHash   string
}

type postActionPlanStep struct {
	credentials   pluginapi.CredentialProvider
	args          pluginapi.ArgsView
	luaRunner     core.PostActionPlanRunner
	qualifiedName string
	kind          core.PostActionPlanStepKind
}

// newPostActionPlan captures request-local inputs before the detached worker starts.
func (b *EffectBridge) newPostActionPlan(
	ctx *gin.Context,
	auth *core.AuthState,
	steps []core.PostActionPlanStep,
) (postActionPlan, error) {
	policyCtx := auth.PolicyDecisionContext(ctx)

	facts, err := pluginEffectFacts(policyCtx)
	if err != nil {
		return postActionPlan{}, err
	}

	requestContext := context.WithoutCancel(contextFromGin(ctx))
	runtimeValues := runtimeSnapshot(auth)
	addPolicyDecisionSources(runtimeValues, policyCtx)

	snapshot := NewRequestSnapshotFromAuthState(auth, WithSnapshotConfig(auth.Cfg()))
	snapshot.ClientNet = policyClientNet(policyCtx, snapshot.ClientNet)

	plan := postActionPlan{
		requestContext: requestContext,
		executionDone:  core.PostActionExecutionDone(ctx),
		runtimeValues:  runtimeValues,
		sourceSteps:    append([]core.PostActionPlanStep(nil), steps...),
		facts:          facts,
		snapshot:       snapshot,
		passwordHash:   postActionPasswordHash(auth),
		steps:          make([]postActionPlanStep, 0, len(steps)),
	}

	for _, requestedStep := range steps {
		step, err := b.newPostActionPlanStep(requestContext, auth, requestedStep)
		if err != nil {
			return postActionPlan{}, err
		}

		plan.steps = append(plan.steps, step)
	}

	return plan, nil
}

// addPolicyDecisionSources mirrors built-in policy outcomes into the public exchange keyspace.
func addPolicyDecisionSources(runtimeValues map[string]any, policyCtx *policycollection.DecisionContext) {
	if runtimeValues == nil {
		return
	}

	policyReport := decisionReport(policyCtx)
	if policyReport == nil {
		return
	}

	sources := exchange.StringList(runtimeValues[exchange.KeyDecisionSources])
	if policyAttributeBool(policyReport, policyAttributeLuaEnvironmentBlocklistTriggered) {
		sources = appendDecisionSource(sources, exchange.FeatureBlocklist)
	}

	if policyAttributeBool(policyReport, policy.AttributeRBLThresholdReached) ||
		policyAttributeBool(policyReport, policy.AttributeRBLError) {
		sources = appendDecisionSource(sources, exchange.FeatureRBL)
	}

	if policyAttributeBool(policyReport, policy.AttributeBruteForceTriggered) ||
		policyAttributeBool(policyReport, policy.AttributeBruteForceError) {
		sources = appendDecisionSource(sources, exchange.FeatureBruteForce)
	}

	if len(sources) > 0 {
		runtimeValues[exchange.KeyDecisionSources] = sources
	}
}

// policyClientNet returns the snapshot value or the brute-force client-net report detail.
func policyClientNet(policyCtx *policycollection.DecisionContext, current string) string {
	if strings.TrimSpace(current) != "" {
		return current
	}

	policyReport := decisionReport(policyCtx)
	if policyReport == nil {
		return ""
	}

	for _, attributeID := range []string{
		policy.AttributeBruteForceTriggered,
		policy.AttributeBruteForceRepeating,
		policy.AttributeBruteForceBucketMatchedCount,
		policy.AttributeBruteForceBucketTriggeredCount,
	} {
		if value := policyDetailString(policyReport, attributeID, policyDetailClientNet); value != "" {
			return value
		}
	}

	return ""
}

// decisionReport safely unwraps the report owned by a policy context.
func decisionReport(policyCtx *policycollection.DecisionContext) *report.DecisionReport {
	if policyCtx == nil {
		return nil
	}

	return policyCtx.Report()
}

// policyAttributeBool reads stable boolean policy attributes from the decision report.
func policyAttributeBool(policyReport *report.DecisionReport, attributeID string) bool {
	if policyReport == nil {
		return false
	}

	attribute, ok := policyReport.Attributes[attributeID]
	if !ok {
		return false
	}

	value, ok := attribute.Value.(bool)

	return ok && value
}

// policyDetailString returns a trimmed string representation of one report detail.
func policyDetailString(policyReport *report.DecisionReport, attributeID string, detailName string) string {
	if policyReport == nil {
		return ""
	}

	attribute, ok := policyReport.Attributes[attributeID]
	if !ok || len(attribute.Details) == 0 {
		return ""
	}

	detail, ok := attribute.Details[detailName]
	if !ok {
		return ""
	}

	return strings.TrimSpace(exchange.StringValue(detail.Value))
}

// appendDecisionSource appends one source while preserving the existing order and uniqueness.
func appendDecisionSource(sources []string, source string) []string {
	source = strings.TrimSpace(source)
	if source == "" {
		return sources
	}

	for _, existing := range sources {
		if existing == source {
			return sources
		}
	}

	return append(sources, source)
}

// newPostActionPlanStep resolves one effect into immutable step inputs.
func (b *EffectBridge) newPostActionPlanStep(
	requestContext context.Context,
	auth *core.AuthState,
	requestedStep core.PostActionPlanStep,
) (postActionPlanStep, error) {
	if requestedStep.Kind() == core.PostActionPlanStepLua {
		runner, ok := requestedStep.LuaStep()
		if !ok {
			return postActionPlanStep{}, fmt.Errorf("lua post-action plan step %q is not runnable", requestedStep.ID())
		}

		return postActionPlanStep{
			luaRunner: runner,
			kind:      core.PostActionPlanStepLua,
		}, nil
	}

	effect, ok := requestedStep.NativeEffect()
	if !ok {
		return postActionPlanStep{}, fmt.Errorf("post-action plan step %q has unsupported kind %q", requestedStep.ID(), requestedStep.Kind())
	}

	if !b.IsPostActionEffect(effect) {
		return postActionPlanStep{}, fmt.Errorf("plugin post-action effect %q is not registered", effect.ID)
	}

	moduleName, err := moduleNameFromQualified(effect.ID)
	if err != nil {
		return postActionPlanStep{}, err
	}

	return postActionPlanStep{
		credentials:   NewCredentialProvider(requestContext, auth.GetPassword(), b.runner.ModuleCapabilities(moduleName)),
		args:          pluginregistry.NewArgsView(effect.Args),
		qualifiedName: effect.ID,
		kind:          core.PostActionPlanStepNative,
	}, nil
}

// runPostActionPlan executes post-action steps sequentially and merges valid runtime deltas.
func (b *EffectBridge) runPostActionPlan(ctx context.Context, plan postActionPlan) (err error) {
	defer core.ReleasePostActionPlanSteps(plan.sourceSteps)

	if err = core.WaitForPostActionExecution(ctx, plan.executionDone); err != nil {
		return err
	}

	tr := monittrace.New("nauthilus/post_action")
	planCtx, planSpan := tr.Start(ctx, "auth.post_action.plan",
		attribute.Int("post_action.steps", len(plan.steps)),
	)

	defer func() {
		if err != nil {
			planSpan.RecordError(err)
			planSpan.SetStatus(codes.Error, "post-action plan failed")
			planSpan.SetAttributes(attribute.String("post_action.result", "error"))
		} else {
			planSpan.SetAttributes(attribute.String("post_action.result", "ok"))
		}

		planSpan.End()
	}()

	runtimeValues, err := cloneRuntimeMap(plan.runtimeValues)
	if err != nil {
		return err
	}

	for _, step := range plan.steps {
		runtimeContext, err := NewRuntimeContext(runtimeValues)
		if err != nil {
			return err
		}

		delta, err := b.runPostActionPlanStep(planCtx, plan, step, runtimeContext, runtimeValues)
		if err != nil {
			return err
		}

		runtimeValues, err = MergeRuntimeDeltas(
			planCtx,
			runtimeValues,
			b.runner.host.Logger(postActionPlanWorkerName),
			delta,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// runPostActionPlanStep executes one native or Lua step against the current plan runtime.
func (b *EffectBridge) runPostActionPlanStep(
	ctx context.Context,
	plan postActionPlan,
	step postActionPlanStep,
	runtimeContext pluginapi.RuntimeContext,
	runtimeValues map[string]any,
) (pluginapi.RuntimeDelta, error) {
	switch step.kind {
	case core.PostActionPlanStepNative:
		result, err := b.runner.EnqueuePostAction(ctx, step.qualifiedName, pluginapi.PostActionRequest{
			Snapshot:     plan.snapshot,
			Runtime:      runtimeContext,
			Credentials:  step.credentials,
			PasswordHash: plan.passwordHash,
			Args:         step.args,
			Facts:        plan.facts,
		})
		if err != nil {
			return pluginapi.RuntimeDelta{}, err
		}

		return result.RuntimeDelta, nil
	case core.PostActionPlanStepLua:
		stepRuntime, err := cloneRuntimeMap(runtimeValues)
		if err != nil {
			return pluginapi.RuntimeDelta{}, err
		}

		delta, ok := step.luaRunner.RunPlanStep(ctx, core.PostActionPlanInput{
			Runtime: stepRuntime,
		})
		if !ok {
			return pluginapi.RuntimeDelta{}, fmt.Errorf("lua post-action plan step failed")
		}

		return delta, nil
	default:
		return pluginapi.RuntimeDelta{}, fmt.Errorf("unsupported post-action plan step kind %q", step.kind)
	}
}

// postActionPasswordHash returns the host-owned short password hash used by Lua post-actions.
func postActionPasswordHash(auth *core.AuthState) string {
	if auth == nil || auth.GetPassword().IsZero() {
		return ""
	}

	var passwordHash string

	auth.GetPassword().WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		options := postActionPasswordHashOptions(auth)
		defer clear(options.Nonce)

		passwordHash = pluginpassword.GenerateHashBytes(value, options)
	})

	return passwordHash
}

// postActionPasswordHashOptions derives host-owned hash inputs without using global util state.
func postActionPasswordHashOptions(auth *core.AuthState) pluginpassword.HashOptions {
	options := pluginpassword.HashOptions{}
	if auth == nil {
		return options
	}

	if auth.Env() != nil {
		options.DevMode = auth.Env().GetDevMode()
	}

	cfg := auth.Cfg()
	if cfg == nil {
		return options
	}

	server := cfg.GetServer()
	if server == nil || server.GetRedis() == nil {
		return options
	}

	server.GetRedis().GetPasswordNonce().WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		options.Nonce = append([]byte(nil), value...)
	})

	return options
}

type pluginEffectRequest struct {
	runtime  pluginapi.RuntimeContext
	args     pluginapi.ArgsView
	facts    []pluginapi.PolicyFact
	snapshot pluginapi.RequestSnapshot
}

func newPluginEffectRequest(
	auth *core.AuthState,
	policyCtx *policycollection.DecisionContext,
	args map[string]any,
) (pluginEffectRequest, error) {
	runtimeContext, err := NewRuntimeContext(runtimeSnapshot(auth))
	if err != nil {
		return pluginEffectRequest{}, err
	}

	facts, err := pluginEffectFacts(policyCtx)
	if err != nil {
		return pluginEffectRequest{}, err
	}

	return pluginEffectRequest{
		snapshot: NewRequestSnapshotFromAuthState(auth, WithSnapshotConfig(auth.Cfg())),
		runtime:  runtimeContext,
		args:     pluginregistry.NewArgsView(args),
		facts:    facts,
	}, nil
}

// pluginEffectFacts exports policy-owned Lua and native plugin facts for effect requests.
func pluginEffectFacts(policyCtx *policycollection.DecisionContext) ([]pluginapi.PolicyFact, error) {
	if policyCtx == nil {
		return nil, nil
	}

	report := policyCtx.Report()
	if report == nil || len(report.Attributes) == 0 {
		return nil, nil
	}

	snapshot := policyCtx.Snapshot()
	if snapshot == nil || len(snapshot.AttributeRegistry) == 0 {
		return nil, nil
	}

	attributeIDs := make([]string, 0, len(report.Attributes))
	for attributeID := range report.Attributes {
		attributeIDs = append(attributeIDs, attributeID)
	}

	sort.Strings(attributeIDs)

	facts := make([]pluginapi.PolicyFact, 0, len(attributeIDs))
	for _, attributeID := range attributeIDs {
		value := report.Attributes[attributeID]

		definition, ok := snapshot.AttributeRegistry[attributeID]
		if !ok || !pluginEffectFactSource(definition.Source) {
			continue
		}

		factValue, err := pluginEffectFactValue(attributeID, value.Value)
		if err != nil {
			return nil, err
		}

		facts = append(facts, pluginapi.PolicyFact{
			Attribute: attributeID,
			Value:     factValue,
		})
	}

	return facts, nil
}

// pluginEffectFactSource limits effect request facts to extension-produced policy facts.
func pluginEffectFactSource(source policyregistry.AttributeSource) bool {
	return source == policyregistry.SourcePlugin || source == policyregistry.SourceLua
}

// pluginEffectFactValue maps policy-native scalar types into plugin API-compatible values.
func pluginEffectFactValue(attributeID string, value any) (any, error) {
	switch typed := value.(type) {
	case netip.Addr:
		return typed.String(), nil
	case netip.Prefix:
		return typed.String(), nil
	case time.Time:
		return typed.Format(time.RFC3339Nano), nil
	default:
		normalized, err := normalizeRuntimeValue(attributeID, value)
		if err != nil {
			return nil, fmt.Errorf("%w: policy fact %q", err, attributeID)
		}

		return normalized, nil
	}
}

// applyPluginEffectFacts validates obligation-emitted facts against auth-decision policy rules.
func applyPluginEffectFacts(policyCtx *policycollection.DecisionContext, facts []pluginapi.PolicyFact) error {
	attributes, err := pluginPolicyFactAttributesForStage(policyCtx, facts, policy.StageAuthDecision)
	if err != nil {
		return err
	}

	for _, attribute := range attributes {
		policyCtx.RecordAttribute(attribute)
	}

	return nil
}

func applyEffectRuntimeDelta(auth *core.AuthState, delta pluginapi.RuntimeDelta) {
	if auth == nil {
		return
	}

	if err := ValidateRuntimeDelta(delta); err != nil {
		return
	}

	if auth.Runtime.Context == nil {
		return
	}

	for _, key := range delta.Delete {
		auth.Runtime.Context.Delete(key)
	}

	for key, value := range delta.Set {
		auth.Runtime.Context.Set(key, value)
	}
}
