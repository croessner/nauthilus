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

package collection

import (
	"context"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/policy/subjectschedule"
)

// ScriptKind identifies the Lua script family observed by the adapter.
type ScriptKind string

const (
	scriptDetailReasonCode    = "reason_code"
	scriptDetailStatusMessage = "status_message"
	scriptReasonLuaError      = "lua_error"

	// ScriptKindEnvironment identifies a Lua environment attribute source.
	ScriptKindEnvironment ScriptKind = "environment"

	// ScriptKindSubject identifies a Lua subject attribute source.
	ScriptKindSubject ScriptKind = "subject"
)

// ScriptResult is the per-script result emitted by Lua runtime adapters.
type ScriptResult struct {
	Err           error
	Kind          ScriptKind
	Name          string
	StatusMessage string
	Duration      time.Duration
	Triggered     bool
	Abort         bool
	Action        bool
}

// ScriptSchedule is one request-local Lua script scheduling entry.
type ScriptSchedule struct {
	Name  string
	After []string
}

// ScriptSchedulePlan describes whether policy checks own a Lua script family.
type ScriptSchedulePlan struct {
	Schedules  []ScriptSchedule
	Configured bool
}

// SubjectScriptPhases partitions Lua subject checks around a native subject boundary.
type SubjectScriptPhases struct {
	Before ScriptSchedulePlan
	After  ScriptSchedulePlan
	Mixed  bool
}

// ScriptRecorder consumes per-script Lua results.
type ScriptRecorder interface {
	RecordScriptResult(context.Context, ScriptResult)
	ScriptScheduled(ScriptKind, string, AuthState) bool
	ScriptPlan(ScriptKind, AuthState) ScriptSchedulePlan
}

// ScriptSink stores Lua script results as policy check facts.
type ScriptSink struct {
	ctx *DecisionContext
}

// NewScriptSink creates a Lua script result sink for the decision context.
func NewScriptSink(ctx *DecisionContext) *ScriptSink {
	return &ScriptSink{ctx: ctx}
}

// RecordScriptResult converts one Lua script result into a check result.
func (s *ScriptSink) RecordScriptResult(ctx context.Context, result ScriptResult) {
	if s == nil || s.ctx == nil || strings.TrimSpace(result.Name) == "" {
		return
	}

	selector := result.selector()
	check := s.ctx.BeginCheck(ctx, selector)
	check.Finish(result.checkResult(s.ctx.Report().Operation))
}

// ScriptScheduled reports whether the active check plan selects a Lua script.
func (s *ScriptSink) ScriptScheduled(kind ScriptKind, name string, authState AuthState) bool {
	if s == nil || s.ctx == nil || strings.TrimSpace(name) == "" {
		return true
	}

	plan := s.ctx.scriptPlan(kind, authState, false)
	if !plan.Configured {
		return true
	}

	for _, schedule := range plan.Schedules {
		if schedule.Name == name {
			return true
		}
	}

	return false
}

// ScriptPlan returns the request-local Lua script plan selected by policy checks.
func (s *ScriptSink) ScriptPlan(kind ScriptKind, authState AuthState) ScriptSchedulePlan {
	if s == nil || s.ctx == nil {
		return ScriptSchedulePlan{}
	}

	return s.ctx.ScriptPlan(kind, authState)
}

// ScriptPlan returns the active Lua script plan for one script family.
func (c *DecisionContext) ScriptPlan(kind ScriptKind, authState AuthState) ScriptSchedulePlan {
	return c.scriptPlan(kind, authState, true)
}

// SubjectScriptPhases returns Lua subject schedules before and after selected native subject dependencies.
func (c *DecisionContext) SubjectScriptPhases(authState AuthState) SubjectScriptPhases {
	plan := c.scriptPlan(ScriptKindSubject, authState, true)
	phases := SubjectScriptPhases{Before: plan}

	if !plan.Configured || len(plan.Schedules) == 0 {
		return phases
	}

	checks := c.selectedSubjectChecks(authState)
	deferred := deferredLuaSubjectNames(checks)

	if len(deferred) == 0 {
		return phases
	}

	phases.Before = filterScriptSchedulePlan(plan, deferred, false)
	phases.After = filterScriptSchedulePlan(plan, deferred, true)
	phases.Mixed = len(phases.After.Schedules) > 0

	return phases
}

// selectedSubjectChecks returns request-selected Lua and native subject checks in policy order.
func (c *DecisionContext) selectedSubjectChecks(authState AuthState) []policyruntime.CompiledCheck {
	checks := make([]policyruntime.CompiledCheck, 0)

	for _, check := range c.stageChecks(policy.StageSubjectAnalysis) {
		if check.Type != policy.CheckTypeLuaSubjectSource && check.Type != policy.CheckTypePluginSubjectSource {
			continue
		}

		if !c.compiledCheckSelected(check, authState) {
			continue
		}

		checks = append(checks, check)
	}

	return checks
}

// deferredLuaSubjectNames finds Lua checks with a selected native dependency in their transitive chain.
func deferredLuaSubjectNames(checks []policyruntime.CompiledCheck) map[string]struct{} {
	deferredChecks := subjectschedule.NewBoundaryGraph(checks).DeferredLuaChecks()
	deferred := make(map[string]struct{})

	for _, check := range checks {
		if check.Type != policy.CheckTypeLuaSubjectSource {
			continue
		}

		if _, exists := deferredChecks[check.Name]; !exists {
			continue
		}

		name := scriptNameFromCheck(ScriptKindSubject, check)
		if name != "" {
			deferred[name] = struct{}{}
		}
	}

	return deferred
}

// filterScriptSchedulePlan keeps one side of the native boundary and removes already-satisfied dependencies.
func filterScriptSchedulePlan(plan ScriptSchedulePlan, selected map[string]struct{}, keepSelected bool) ScriptSchedulePlan {
	keptNames := make(map[string]struct{})

	for _, schedule := range plan.Schedules {
		_, exists := selected[schedule.Name]
		if exists == keepSelected {
			keptNames[schedule.Name] = struct{}{}
		}
	}

	schedules := make([]ScriptSchedule, 0, len(keptNames))
	for _, schedule := range plan.Schedules {
		if _, keep := keptNames[schedule.Name]; !keep {
			continue
		}

		dependencies := make([]string, 0, len(schedule.After))
		for _, dependency := range schedule.After {
			if _, keep := keptNames[dependency]; keep {
				dependencies = append(dependencies, dependency)
			}
		}

		schedules = append(schedules, ScriptSchedule{Name: schedule.Name, After: dependencies})
	}

	return ScriptSchedulePlan{Schedules: schedules, Configured: plan.Configured}
}

func (c *DecisionContext) scriptPlan(kind ScriptKind, authState AuthState, recordSkips bool) ScriptSchedulePlan {
	if c == nil || c.snapshot == nil || c.report == nil {
		return ScriptSchedulePlan{}
	}

	selector := ScriptResult{Kind: kind}.selector()

	checks := c.stageChecks(selector.Stage)
	if len(checks) == 0 {
		return ScriptSchedulePlan{}
	}

	selected := make([]scriptPlanCheck, 0)
	configured := false

	for _, check := range checks {
		if check.Type != selector.CheckType {
			continue
		}

		configured = true

		name := scriptNameFromCheck(kind, check)
		if name == "" || !c.scriptCheckScheduled(check, authState, recordSkips) {
			continue
		}

		selected = append(selected, scriptPlanCheck{
			name:  name,
			check: check.Name,
			after: append([]string(nil), check.After...),
		})
	}

	if !configured {
		return ScriptSchedulePlan{}
	}

	return ScriptSchedulePlan{
		Schedules:  scriptSchedules(selected),
		Configured: true,
	}
}

func (c *DecisionContext) scriptCheckScheduled(
	check policyruntime.CompiledCheck,
	authState AuthState,
	recordSkips bool,
) bool {
	if recordSkips {
		return c.compiledCheckScheduled(context.Background(), check, authState)
	}

	return c.compiledCheckSelected(check, authState)
}

func (r ScriptResult) selector() CheckSelector {
	switch r.Kind {
	case ScriptKindSubject:
		return CheckSelector{
			CheckType: policy.CheckTypeLuaSubjectSource,
			Stage:     policy.StageSubjectAnalysis,
			Name:      "lua_subject_" + r.Name,
			ConfigRef: "auth.policy.attribute_sources.lua.subject." + r.Name,
		}
	default:
		return CheckSelector{
			CheckType: policy.CheckTypeLuaEnvironment,
			Stage:     policy.StagePreAuth,
			Name:      "lua_environment_" + r.Name,
			ConfigRef: "auth.policy.attribute_sources.lua.environment." + r.Name,
		}
	}
}

type scriptPlanCheck struct {
	name  string
	check string
	after []string
}

func scriptSchedules(checks []scriptPlanCheck) []ScriptSchedule {
	if len(checks) == 0 {
		return nil
	}

	nameByCheck := make(map[string]string, len(checks))
	for _, check := range checks {
		nameByCheck[check.check] = check.name
	}

	schedules := make([]ScriptSchedule, 0, len(checks))
	for _, check := range checks {
		schedules = append(schedules, ScriptSchedule{
			Name:  check.name,
			After: scriptScheduleDependencies(check.after, nameByCheck),
		})
	}

	return schedules
}

func scriptScheduleDependencies(after []string, nameByCheck map[string]string) []string {
	if len(after) == 0 {
		return nil
	}

	dependencies := make([]string, 0, len(after))
	for _, dependency := range after {
		if scriptName, exists := nameByCheck[dependency]; exists {
			dependencies = append(dependencies, scriptName)
		}
	}

	return dependencies
}

func scriptNameFromCheck(kind ScriptKind, check policyruntime.CompiledCheck) string {
	if name := scriptNameFromConfigRef(kind, check.ConfigRef); name != "" {
		return name
	}

	return scriptNameFromCheckName(kind, check.Name)
}

func scriptNameFromConfigRef(kind ScriptKind, configRef string) string {
	prefix := "auth.policy.attribute_sources.lua.environment."
	if kind == ScriptKindSubject {
		prefix = "auth.policy.attribute_sources.lua.subject."
	}

	name := strings.TrimPrefix(configRef, prefix)
	if name == configRef {
		return ""
	}

	return strings.TrimSpace(name)
}

func scriptNameFromCheckName(kind ScriptKind, checkName string) string {
	prefix := "lua_environment_"
	if kind == ScriptKindSubject {
		prefix = "lua_subject_"
	}

	name := strings.TrimPrefix(checkName, prefix)
	if name == checkName {
		return ""
	}

	return strings.TrimSpace(name)
}

func (r ScriptResult) checkResult(operation policy.Operation) CheckResult {
	switch r.Kind {
	case ScriptKindSubject:
		return r.subjectResult(operation)
	default:
		return r.environmentResult(operation)
	}
}

func (r ScriptResult) environmentResult(operation policy.Operation) CheckResult {
	attributes := []AttributeValue{
		BoolAttribute(scriptAttributeID(r.Kind, r.Name, "triggered"), policy.StagePreAuth, operation, r.Triggered, statusMessageDetails(r.StatusMessage)),
		BoolAttribute(scriptAttributeID(r.Kind, r.Name, "abort"), policy.StagePreAuth, operation, r.Abort, nil),
	}

	if r.Err != nil {
		attributes = append(attributes, BoolAttribute(scriptAttributeID(r.Kind, r.Name, "error"), policy.StagePreAuth, operation, true, map[string]DetailValue{
			scriptDetailReasonCode: InternalDetail(scriptReasonLuaError),
		}))
	}

	return CheckResult{
		Err:          r.Err,
		Status:       statusFromError(r.Err),
		Matched:      r.Triggered || r.Abort,
		DecisionHint: environmentDecision(r),
		Reason:       reasonFromError(r.Err),
		Duration:     r.Duration,
		Attributes:   attributes,
	}
}

func (r ScriptResult) subjectResult(operation policy.Operation) CheckResult {
	attributes := []AttributeValue{
		BoolAttribute(scriptAttributeID(r.Kind, r.Name, "rejected"), policy.StageSubjectAnalysis, operation, r.Action, statusMessageDetails(r.StatusMessage)),
	}

	if r.Err != nil {
		attributes = append(attributes, BoolAttribute(scriptAttributeID(r.Kind, r.Name, "error"), policy.StageSubjectAnalysis, operation, true, map[string]DetailValue{
			scriptDetailReasonCode: InternalDetail(scriptReasonLuaError),
		}))
	}

	return CheckResult{
		Err:          r.Err,
		Status:       statusFromError(r.Err),
		Matched:      r.Action,
		DecisionHint: subjectDecision(r),
		Reason:       reasonFromError(r.Err),
		Duration:     r.Duration,
		Attributes:   attributes,
	}
}

func (k ScriptKind) policySegment() string {
	switch k {
	case ScriptKindSubject:
		return "subject"
	default:
		return "environment"
	}
}

func statusMessageDetails(message string) map[string]DetailValue {
	if message == "" {
		return nil
	}

	return map[string]DetailValue{
		scriptDetailStatusMessage: PublicMessageDetail(message),
	}
}

func statusFromError(err error) policy.CheckStatus {
	if err != nil {
		return policy.CheckStatusError
	}

	return policy.CheckStatusOK
}

func reasonFromError(err error) string {
	if err != nil {
		return "lua_error"
	}

	return ""
}

func environmentDecision(result ScriptResult) policy.Decision {
	if result.Err != nil {
		return policy.DecisionTempFail
	}

	if result.Triggered {
		return policy.DecisionDeny
	}

	return policy.DecisionNeutral
}

func subjectDecision(result ScriptResult) policy.Decision {
	if result.Err != nil {
		return policy.DecisionTempFail
	}

	if result.Action {
		return policy.DecisionDeny
	}

	return policy.DecisionNeutral
}
