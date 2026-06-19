// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"maps"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/lualib/pipeline"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/policy"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
)

const (
	pluginEnvironmentCheckPrefix     = "plugin_environment_"
	pluginEnvironmentConfigRefPrefix = "plugins.modules."
)

var _ core.PluginEnvironmentSourceBridge = (*EnvironmentSourceBridge)(nil)

// EnvironmentSourceBridge adapts native plugin environment sources into the pre-auth flow.
type EnvironmentSourceBridge struct {
	runner *Runner
}

// NewEnvironmentSourceBridge returns a bridge bound to one plugin runner.
func NewEnvironmentSourceBridge(runner *Runner) *EnvironmentSourceBridge {
	return &EnvironmentSourceBridge{runner: runner}
}

// Evaluate executes registered native environment sources before built-in environment controls.
func (b *EnvironmentSourceBridge) Evaluate(
	ctx *gin.Context,
	view *core.StateView,
) (triggered bool, abort bool, handled bool, err error) {
	auth := authFromView(view)
	if b == nil || b.runner == nil || auth == nil || b.runner.registry == nil {
		return false, false, false, nil
	}

	components := b.runner.registry.EnvironmentSources()
	if len(components) == 0 {
		return false, false, false, nil
	}

	outcome, err := b.evaluate(ctx, auth, components)
	if err != nil {
		return false, false, true, err
	}

	return outcome.triggered, outcome.abort, true, nil
}

type environmentBridgeOutcome struct {
	triggered bool
	abort     bool
}

type environmentExecutionResult struct {
	err       error
	component pluginregistry.Component
	result    pluginapi.EnvironmentResult
	duration  time.Duration
	index     int
}

// evaluate runs the environment source dependency plan and applies each level in order.
func (b *EnvironmentSourceBridge) evaluate(
	ctx *gin.Context,
	auth *core.AuthState,
	components []pluginregistry.Component,
) (environmentBridgeOutcome, error) {
	plan, err := environmentPlan(components)
	if err != nil {
		return environmentBridgeOutcome{}, err
	}

	runtimeValues := runtimeSnapshot(auth)
	policyCtx := auth.PolicyDecisionContext(ctx)
	outcome := environmentBridgeOutcome{}

	for _, level := range plan.Levels {
		levelResults, err := b.evaluateEnvironmentLevel(ctx, auth, runtimeValues, level)
		if err != nil {
			return environmentBridgeOutcome{}, err
		}

		if err := applyEnvironmentLevelResults(ctx, auth, policyCtx, runtimeValues, levelResults, &outcome); err != nil {
			return environmentBridgeOutcome{}, err
		}

		if outcome.abort {
			break
		}
	}

	applyRuntimeValues(auth, runtimeValues)

	return outcome, nil
}

// evaluateEnvironmentLevel executes one dependency level concurrently.
func (b *EnvironmentSourceBridge) evaluateEnvironmentLevel(
	ctx *gin.Context,
	auth *core.AuthState,
	runtimeValues map[string]any,
	level []pipeline.PlannedNode,
) ([]environmentExecutionResult, error) {
	results := make([]environmentExecutionResult, len(level))
	group, groupCtx := errgroup.WithContext(contextFromGin(ctx))

	for levelIndex, planned := range level {
		component := planned.Value.(pluginregistry.Component)

		group.Go(func() error {
			result := environmentExecutionResult{
				component: component,
				index:     planned.Index,
			}
			started := time.Now()

			request, err := environmentRequest(b.runner, auth, component, runtimeValues)
			if err != nil {
				result.err = err
				result.duration = time.Since(started)
				results[levelIndex] = result

				return err
			}

			callCtx, cancel := subjectCallContext(groupCtx, component.SourceDescriptor.Timeout)
			defer cancel()

			result.result, result.err = b.runner.EvaluateEnvironment(callCtx, component.QualifiedName, request)
			result.duration = time.Since(started)
			results[levelIndex] = result

			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return results, err
	}

	sortEnvironmentResults(results)

	return results, nil
}

// applyEnvironmentLevelResults records policy evidence and merges runtime deltas for one level.
func applyEnvironmentLevelResults(
	ctx *gin.Context,
	auth *core.AuthState,
	policyCtx *policycollection.DecisionContext,
	runtimeValues map[string]any,
	results []environmentExecutionResult,
	outcome *environmentBridgeOutcome,
) error {
	deltas := make([]pluginapi.RuntimeDelta, 0, len(results))

	for _, item := range results {
		factAttributes, factErr := pluginPolicyFactAttributesForStage(policyCtx, item.result.Facts, policy.StagePreAuth)
		recordPluginEnvironmentResult(ctx, policyCtx, item, factAttributes, factErr)

		if item.err != nil {
			return item.err
		}

		applyPluginStatus(auth, item.result.Status)
		applySubjectLogs(auth, item.result.Logs)

		if factErr != nil {
			return factErr
		}

		deltas = append(deltas, item.result.RuntimeDelta)
		outcome.triggered = outcome.triggered || item.result.Triggered
		outcome.abort = outcome.abort || item.result.Abort
	}

	merged, err := MergeRuntimeDeltas(contextFromGin(ctx), runtimeValues, nil, deltas...)
	if err != nil {
		return err
	}

	clearMap(runtimeValues)

	maps.Copy(runtimeValues, merged)

	return nil
}

// environmentPlan builds the dependency plan for pre-auth environment sources.
func environmentPlan(components []pluginregistry.Component) (pipeline.Plan, error) {
	nodes := make([]pipeline.Node, 0, len(components))
	for index, component := range components {
		dependencies := append([]string(nil), component.SourceDescriptor.Requires...)
		dependencies = append(dependencies, component.SourceDescriptor.After...)
		nodes = append(nodes, pipeline.Node{
			Name:      component.QualifiedName,
			DependsOn: dependencies,
			Index:     index,
			Modes:     pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth,
			Value:     component,
		})
	}

	return pipeline.BuildPlan(nodes, pipeline.ModeUnauthenticated|pipeline.ModeNoAuth|pipeline.ModeAuthenticated)
}

// environmentRequest maps AuthState into the stable plugin API request shape.
func environmentRequest(
	runner *Runner,
	auth *core.AuthState,
	component pluginregistry.Component,
	runtimeValues map[string]any,
) (pluginapi.EnvironmentRequest, error) {
	runtimeContext, err := NewRuntimeContext(runtimeValues)
	if err != nil {
		return pluginapi.EnvironmentRequest{}, err
	}

	return pluginapi.EnvironmentRequest{
		Snapshot:    NewRequestSnapshotFromAuthState(auth, WithSnapshotConfig(auth.Cfg())),
		Runtime:     runtimeContext,
		Credentials: NewCredentialProvider(auth.Ctx(), auth.GetPassword(), subjectRunnerCapabilities(runner, component.ModuleName)),
	}, nil
}

// recordPluginEnvironmentResult writes plugin environment facts and check evidence into the policy report.
func recordPluginEnvironmentResult(
	ctx *gin.Context,
	policyCtx *policycollection.DecisionContext,
	item environmentExecutionResult,
	factAttributes []policycollection.AttributeValue,
	factErr error,
) {
	if policyCtx == nil || item.component.QualifiedName == "" {
		return
	}

	attributes := []policycollection.AttributeValue{
		policycollection.BoolAttribute(
			pluginEnvironmentAttributeID(item.component, "triggered"),
			policy.StagePreAuth,
			policyCtx.Report().Operation,
			item.result.Triggered,
			pluginStatusDetails(item.result.Status),
		),
		policycollection.BoolAttribute(
			pluginEnvironmentAttributeID(item.component, "abort"),
			policy.StagePreAuth,
			policyCtx.Report().Operation,
			item.result.Abort,
			nil,
		),
	}

	if factErr == nil {
		attributes = append(attributes, factAttributes...)
	} else if item.err == nil {
		item.err = factErr
	}

	if item.err != nil {
		attributes = append(attributes, policycollection.BoolAttribute(
			pluginEnvironmentAttributeID(item.component, "error"),
			policy.StagePreAuth,
			policyCtx.Report().Operation,
			true,
			map[string]policycollection.DetailValue{pluginErrorDetailKey: policycollection.InternalDetail(pluginErrorReason)},
		))
	}

	check := policyCtx.BeginCheck(contextFromGin(ctx), policycollection.CheckSelector{
		CheckType: policy.CheckTypePluginEnvironment,
		Stage:     policy.StagePreAuth,
		Name:      pluginEnvironmentCheckName(item.component),
		ConfigRef: pluginEnvironmentConfigRef(item.component),
	})
	check.Finish(policycollection.CheckResult{
		Err:          item.err,
		Status:       pluginSubjectStatus(item.err),
		Reason:       pluginSubjectReason(item.err),
		Matched:      item.result.Triggered || item.result.Abort || item.err != nil,
		DecisionHint: pluginEnvironmentDecision(item.result.Triggered, item.err),
		Duration:     item.duration,
		Attributes:   attributes,
	})
}

// pluginEnvironmentCheckName returns the scheduler-visible check name for one module.
func pluginEnvironmentCheckName(component pluginregistry.Component) string {
	return pluginEnvironmentCheckPrefix + component.ModuleName
}

// pluginEnvironmentConfigRef returns the module config reference used to match compiled checks.
func pluginEnvironmentConfigRef(component pluginregistry.Component) string {
	return pluginEnvironmentConfigRefPrefix + component.ModuleName + ".environment"
}

// pluginEnvironmentAttributeID returns a bounded policy attribute id for plugin environment evidence.
func pluginEnvironmentAttributeID(component pluginregistry.Component, suffix string) string {
	return "auth.plugin.environment." + component.ModuleName + "." + component.LocalName + "." + suffix
}

// pluginEnvironmentDecision maps a plugin environment result into the policy report decision hint.
func pluginEnvironmentDecision(triggered bool, err error) policy.Decision {
	if err != nil {
		return policy.DecisionTempFail
	}

	if triggered {
		return policy.DecisionDeny
	}

	return policy.DecisionNeutral
}

// sortEnvironmentResults restores registration order after concurrent execution.
func sortEnvironmentResults(results []environmentExecutionResult) {
	for i := 1; i < len(results); i++ {
		item := results[i]

		j := i - 1
		for j >= 0 && results[j].index > item.index {
			results[j+1] = results[j]
			j--
		}

		results[j+1] = item
	}
}
