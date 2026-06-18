package pluginruntime

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/pluginregistry"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
	"github.com/croessner/nauthilus/server/policy/report"

	"github.com/gin-gonic/gin"
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
		return true, b.enqueuePostAction(ctx, auth, effect)
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

func (b *EffectBridge) enqueuePostAction(ctx *gin.Context, auth *core.AuthState, effect report.EffectRequest) bool {
	if b.runner.host == nil {
		return false
	}

	policyCtx := auth.PolicyDecisionContext(ctx)

	request, err := newPluginEffectRequest(auth, policyCtx, effect.Args)
	if err != nil {
		return false
	}

	b.runner.host.Go(contextFromGin(ctx), effect.ID, func(workerCtx context.Context) error {
		_, err = b.runner.EnqueuePostAction(workerCtx, effect.ID, pluginapi.PostActionRequest{
			Snapshot: request.snapshot,
			Runtime:  request.runtime,
			Args:     request.args,
			Facts:    request.facts,
		})

		return err
	})

	return true
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
