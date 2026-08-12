package pluginruntime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/pluginapi/v1/exchange"
	pluginpassword "github.com/croessner/nauthilus/v3/pluginapi/v1/password"
	"github.com/croessner/nauthilus/v3/server/core"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/policy"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	"github.com/croessner/nauthilus/v3/server/policy/report"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var _ core.PluginEffectBridge = (*EffectBridge)(nil)

var errPostActionDispatchAmbiguous = errors.New("post-action external dispatch outcome is unknown")

// EffectBridge adapts policy-selected native plugin effects into core.
type EffectBridge struct {
	runner       *Runner
	planObserver postActionPlanObserver
}

// NewEffectBridge returns an effect bridge bound to one plugin runner.
func NewEffectBridge(runner *Runner) *EffectBridge {
	return &EffectBridge{
		runner:       runner,
		planObserver: newPostActionPlanObserver(),
	}
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

// EnqueuePostActionPlan synchronously transfers one ordered plan to the host supervisor.
func (b *EffectBridge) EnqueuePostActionPlan(
	ctx *gin.Context,
	view *core.StateView,
	steps []core.PostActionPlanStep,
) (bool, bool) {
	auth := authFromView(view)
	if b == nil || b.runner == nil || b.runner.postActions == nil || auth == nil || len(steps) == 0 {
		return false, false
	}

	plan, err := b.newPostActionPlan(ctx, auth, steps)
	if err != nil {
		core.ReleasePostActionPlanSteps(steps)

		return true, false
	}

	for index, work := range plan.works {
		if _, err = b.runner.postActions.Accept(ctx, view, work.ordinal, work); err != nil {
			for _, rejected := range plan.works[index:] {
				rejected.Cleanup()
			}

			return true, false
		}
	}

	return true, true
}

const postActionPlanWorkerName = "post_action_plan"

const (
	policyAttributeLuaEnvironmentBlocklistTriggered = "auth.lua.environment.blocklist.triggered"
	policyDetailClientNet                           = "client_net"
)

type postActionPlan struct {
	runtimeValues map[string]any
	sourceSteps   []core.PostActionPlanStep
	steps         []postActionPlanStep
	facts         []pluginapi.PolicyFact
	snapshot      pluginapi.RequestSnapshot
	passwordHash  string
	bridge        *EffectBridge
	works         []*postActionEffectWork
	remaining     int
	mu            sync.Mutex
}

type postActionPlanStep struct {
	credentials   pluginapi.CredentialProvider
	args          pluginapi.ArgsView
	luaRunner     core.PostActionPlanRunner
	qualifiedName string
	kind          core.PostActionPlanStepKind
}

type postActionCaptureBounds struct {
	runtime      map[string]any
	args         []map[string]any
	facts        []pluginapi.PolicyFact
	snapshot     pluginapi.RequestSnapshot
	passwordHash string
}

type postActionEffectWork struct {
	plan        *postActionPlan
	previous    <-chan bool
	completed   chan bool
	index       int
	ordinal     uint32
	finishOnce  sync.Once
	cleanupOnce sync.Once
}

// newPostActionPlan captures request-local inputs before the detached worker starts.
func (b *EffectBridge) newPostActionPlan(
	ctx *gin.Context,
	auth *core.AuthState,
	steps []core.PostActionPlanStep,
) (*postActionPlan, error) {
	policyCtx := auth.PolicyDecisionContext(ctx)

	facts, err := pluginEffectFacts(policyCtx)
	if err != nil {
		return nil, err
	}

	requestContext := context.WithoutCancel(contextFromGin(ctx))

	runtimeValues, err := cloneRuntimeMap(runtimeSnapshot(auth))
	if err != nil {
		return nil, err
	}

	addPolicyDecisionSources(runtimeValues, policyCtx)

	snapshot := NewRequestSnapshotFromAuthState(auth, WithSnapshotConfig(auth.Cfg()))
	snapshot.ClientNet = policyClientNet(policyCtx, snapshot.ClientNet)
	passwordHash := postActionPasswordHash(auth)

	if err := validatePostActionCaptureBounds(runtimeValues, facts, snapshot, passwordHash, steps); err != nil {
		return nil, err
	}

	plan := &postActionPlan{
		runtimeValues: runtimeValues,
		sourceSteps:   append([]core.PostActionPlanStep(nil), steps...),
		facts:         facts,
		snapshot:      snapshot,
		passwordHash:  passwordHash,
		steps:         make([]postActionPlanStep, 0, len(steps)),
		bridge:        b,
	}

	for _, requestedStep := range steps {
		step, err := b.newPostActionPlanStep(requestContext, auth, requestedStep)
		if err != nil {
			plan.Cleanup()

			return nil, err
		}

		plan.steps = append(plan.steps, step)
	}

	plan.works = newPostActionEffectWorks(plan)
	plan.remaining = len(plan.works)

	return plan, nil
}

// validatePostActionCaptureBounds rejects oversized concrete work before acceptance.
func validatePostActionCaptureBounds(
	runtimeValues map[string]any,
	facts []pluginapi.PolicyFact,
	snapshot pluginapi.RequestSnapshot,
	passwordHash string,
	steps []core.PostActionPlanStep,
) error {
	args := make([]map[string]any, 0, len(steps))
	for _, step := range steps {
		if effect, ok := step.NativeEffect(); ok {
			args = append(args, effect.Args)
		}
	}

	return effectsupervisor.ValidateBoundedValue(postActionCaptureBounds{
		runtime:      runtimeValues,
		args:         args,
		facts:        facts,
		snapshot:     snapshot,
		passwordHash: passwordHash,
	}, effectsupervisor.DefaultWorkBounds())
}

// newPostActionEffectWorks creates one ordered supervisor owner per effect ordinal.
func newPostActionEffectWorks(plan *postActionPlan) []*postActionEffectWork {
	previous := make(chan bool, 1)
	previous <- true

	works := make([]*postActionEffectWork, 0, len(plan.steps))

	for index := range plan.steps {
		completed := make(chan bool, 1)
		ordinal := plan.sourceSteps[index].EffectOrdinal()

		if ordinal == 0 {
			ordinal = uint32(index + 1)
		}

		works = append(works, &postActionEffectWork{
			plan:      plan,
			previous:  previous,
			completed: completed,
			index:     index,
			ordinal:   ordinal,
		})
		previous = completed
	}

	return works
}

// Validate confirms that the captured plugin plan has one runtime owner and executable step.
func (p *postActionPlan) Validate() error {
	if p == nil || p.bridge == nil || p.bridge.runner == nil || len(p.steps) == 0 {
		return effectsupervisor.ErrInvalidWork
	}

	return nil
}

// Execute invokes the captured ordered plan once without automatic retry.
func (p *postActionPlan) Execute(ctx context.Context) effectsupervisor.Result {
	return postActionExecutionResult(p.bridge.runPostActionPlan(ctx, p))
}

// Cleanup releases copied source steps and sensitive values exactly once.
func (p *postActionPlan) Cleanup() {
	if p == nil {
		return
	}

	if len(p.works) == 0 {
		core.ReleasePostActionPlanSteps(p.sourceSteps)
		p.clear()

		return
	}

	for _, work := range p.works {
		work.Cleanup()
	}
}

// Validate confirms that one selected effect has an immutable sequence owner.
func (w *postActionEffectWork) Validate() error {
	if w == nil || w.plan == nil || w.previous == nil || w.completed == nil || w.index < 0 || w.index >= len(w.plan.steps) {
		return effectsupervisor.ErrInvalidWork
	}

	return nil
}

// Execute waits for the prior effect and invokes its selected provider exactly once.
func (w *postActionEffectWork) Execute(ctx context.Context) effectsupervisor.Result {
	select {
	case proceed := <-w.previous:
		if !proceed {
			w.finish(false)

			return effectsupervisor.Failed("prior_step_failed")
		}
	case <-ctx.Done():
		w.finish(false)

		return effectsupervisor.Failed("canceled")
	}

	err := w.plan.bridge.runPostActionPlanEffect(ctx, w.plan, w.index)
	w.finish(err == nil)

	return postActionExecutionResult(err)
}

// Cleanup releases one captured effect and clears shared state after the last owner.
func (w *postActionEffectWork) Cleanup() {
	if w == nil {
		return
	}

	w.cleanupOnce.Do(func() {
		w.finish(false)
		w.plan.sourceSteps[w.index].Release()

		w.plan.mu.Lock()
		w.plan.remaining--
		last := w.plan.remaining == 0
		w.plan.mu.Unlock()

		if last {
			w.plan.clear()
		}
	})
}

// finish publishes whether the next selected effect may execute.
func (w *postActionEffectWork) finish(proceed bool) {
	w.finishOnce.Do(func() {
		w.completed <- proceed
	})
}

// clear drops shared captured values after every effect owner releases them.
func (p *postActionPlan) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.sourceSteps = nil
	p.steps = nil
	p.works = nil
	p.runtimeValues = nil
	p.facts = nil
	p.passwordHash = ""
}

// postActionExecutionResult maps plugin execution into a bounded supervisor outcome.
func postActionExecutionResult(err error) effectsupervisor.Result {
	if err == nil {
		return effectsupervisor.Succeeded()
	}

	if errors.Is(err, errPostActionDispatchAmbiguous) {
		return effectsupervisor.OutcomeUnknown("dispatch_ambiguous")
	}

	return effectsupervisor.Failed("provider_failure")
}

// WaitPostActions waits for every plan accepted by this bridge generation.
func (b *EffectBridge) WaitPostActions(ctx context.Context) error {
	if b == nil || b.runner == nil || b.runner.postActions == nil {
		return nil
	}

	return b.runner.postActions.WaitIdle(ctx)
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

		if err := runner.ValidatePlanStep(); err != nil {
			return postActionPlanStep{}, err
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

	args, err := cloneRuntimeMap(effect.Args)
	if err != nil {
		return postActionPlanStep{}, err
	}

	return postActionPlanStep{
		credentials:   NewCredentialProvider(requestContext, auth.GetPassword(), b.runner.ModuleCapabilities(moduleName)),
		args:          pluginregistry.NewArgsView(args),
		qualifiedName: effect.ID,
		kind:          core.PostActionPlanStepNative,
	}, nil
}

// runPostActionPlan executes post-action steps sequentially and merges valid runtime deltas.
func (b *EffectBridge) runPostActionPlan(ctx context.Context, plan *postActionPlan) (err error) {
	if plan == nil {
		return effectsupervisor.ErrInvalidWork
	}

	for index := range plan.steps {
		if err := b.runPostActionPlanEffect(ctx, plan, index); err != nil {
			return err
		}
	}

	return nil
}

// runPostActionPlanEffect executes one selected effect against ordered shared runtime state.
func (b *EffectBridge) runPostActionPlanEffect(ctx context.Context, plan *postActionPlan, index int) (err error) {
	if plan == nil || index < 0 || index >= len(plan.steps) {
		return effectsupervisor.ErrInvalidWork
	}

	ordinal := uint32(index + 1)
	if index < len(plan.works) {
		ordinal = plan.works[index].ordinal
	}

	tr := monittrace.New("nauthilus/post_action")
	planCtx, planSpan := tr.Start(ctx, "auth.post_action.plan",
		attribute.Int("post_action.steps", 1),
		attribute.Int("post_action.effect_ordinal", int(ordinal)),
	)
	startedAt := time.Now()

	defer func() {
		b.finishPostActionPlanEffect(planSpan, startedAt, err)
	}()

	plan.mu.Lock()
	runtimeValues, err := cloneRuntimeMap(plan.runtimeValues)
	plan.mu.Unlock()
	if err != nil {
		return err
	}

	runtimeContext, err := NewRuntimeContext(runtimeValues)
	if err != nil {
		return err
	}

	delta, err := b.runPostActionPlanStep(planCtx, plan, plan.steps[index], runtimeContext, runtimeValues)
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

	plan.mu.Lock()
	plan.runtimeValues = runtimeValues
	plan.mu.Unlock()

	return nil
}

// finishPostActionPlanEffect records the terminal duration and span result for one selected effect.
func (b *EffectBridge) finishPostActionPlanEffect(span trace.Span, startedAt time.Time, err error) {
	b.planObserver.Observe(time.Since(startedAt), pluginCallResult(CallRecord{Err: err}))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "post-action plan failed")
		span.SetAttributes(attribute.String("post_action.result", "error"))
	} else {
		span.SetAttributes(attribute.String("post_action.result", "ok"))
	}

	span.End()
}

// runPostActionPlanStep executes one native or Lua step against the current plan runtime.
func (b *EffectBridge) runPostActionPlanStep(
	ctx context.Context,
	plan *postActionPlan,
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
			if errors.Is(err, errPostActionWorkerFailed) {
				return pluginapi.RuntimeDelta{}, err
			}

			if result.Enqueued {
				return pluginapi.RuntimeDelta{}, errors.Join(errPostActionDispatchAmbiguous, err)
			}

			return pluginapi.RuntimeDelta{}, err
		}

		return result.RuntimeDelta, nil
	case core.PostActionPlanStepLua:
		stepRuntime, err := cloneRuntimeMap(runtimeValues)
		if err != nil {
			return pluginapi.RuntimeDelta{}, err
		}

		delta, result := step.luaRunner.RunPlanStep(ctx, core.PostActionPlanInput{
			Runtime: stepRuntime,
		})
		switch result.State() {
		case effectsupervisor.StateSucceeded:
			return delta, nil
		case effectsupervisor.StateOutcomeUnknown:
			return pluginapi.RuntimeDelta{}, errPostActionDispatchAmbiguous
		default:
			return pluginapi.RuntimeDelta{}, fmt.Errorf("lua post-action plan step failed")
		}
	default:
		return pluginapi.RuntimeDelta{}, fmt.Errorf("unsupported post-action plan step kind %q", step.kind)
	}
}

// postActionPasswordHash returns the host-owned full password hash used by post-actions.
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

	attributeIDs := make([]string, 0, len(report.Attributes))
	for attributeID := range report.Attributes {
		attributeIDs = append(attributeIDs, attributeID)
	}

	sort.Strings(attributeIDs)

	facts := make([]pluginapi.PolicyFact, 0, len(attributeIDs))
	for _, attributeID := range attributeIDs {
		value := report.Attributes[attributeID]

		definition, ok := policyCtx.AttributeDefinition(attributeID)
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
