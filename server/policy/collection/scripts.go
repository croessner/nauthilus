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

	"github.com/croessner/nauthilus/server/policy"
)

// ScriptKind identifies the Lua script family observed by the adapter.
type ScriptKind string

const (
	// ScriptKindControl identifies a Lua control script.
	ScriptKindControl ScriptKind = "control"

	// ScriptKindFilter identifies a Lua filter script.
	ScriptKindFilter ScriptKind = "filter"
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

// ScriptRecorder consumes per-script Lua results.
type ScriptRecorder interface {
	RecordScriptResult(context.Context, ScriptResult)
	ScriptScheduled(ScriptKind, string, AuthState) bool
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

	selector := ScriptResult{Kind: kind, Name: name}.selector()

	return s.ctx.ScriptScheduled(selector, authState)
}

func (r ScriptResult) selector() CheckSelector {
	switch r.Kind {
	case ScriptKindFilter:
		return CheckSelector{
			CheckType: policy.CheckTypeLuaFilter,
			Stage:     policy.StageAuthFilters,
			Name:      "lua_filter_" + r.Name,
			ConfigRef: "auth.controls.lua.filters." + r.Name,
		}
	default:
		return CheckSelector{
			CheckType: policy.CheckTypeLuaControl,
			Stage:     policy.StagePreAuth,
			Name:      "lua_control_" + r.Name,
			ConfigRef: "auth.controls.lua.controls." + r.Name,
		}
	}
}

func (r ScriptResult) checkResult(operation policy.Operation) CheckResult {
	switch r.Kind {
	case ScriptKindFilter:
		return r.filterResult(operation)
	default:
		return r.controlResult(operation)
	}
}

func (r ScriptResult) controlResult(operation policy.Operation) CheckResult {
	attributes := []AttributeValue{
		BoolAttribute(scriptAttributeID(r.Kind, r.Name, "triggered"), policy.StagePreAuth, operation, r.Triggered, statusMessageDetails(r.StatusMessage)),
		BoolAttribute(scriptAttributeID(r.Kind, r.Name, "abort"), policy.StagePreAuth, operation, r.Abort, nil),
	}

	if r.Err != nil {
		attributes = append(attributes, BoolAttribute(scriptAttributeID(r.Kind, r.Name, "error"), policy.StagePreAuth, operation, true, map[string]DetailValue{
			"reason_code": InternalDetail("lua_error"),
		}))
	}

	return CheckResult{
		Err:          r.Err,
		Status:       statusFromError(r.Err),
		Matched:      r.Triggered || r.Abort,
		DecisionHint: controlDecision(r),
		Reason:       reasonFromError(r.Err),
		Duration:     r.Duration,
		Attributes:   attributes,
	}
}

func (r ScriptResult) filterResult(operation policy.Operation) CheckResult {
	attributes := []AttributeValue{
		BoolAttribute(scriptAttributeID(r.Kind, r.Name, "rejected"), policy.StageAuthFilters, operation, r.Action, statusMessageDetails(r.StatusMessage)),
	}

	if r.Err != nil {
		attributes = append(attributes, BoolAttribute(scriptAttributeID(r.Kind, r.Name, "error"), policy.StageAuthFilters, operation, true, map[string]DetailValue{
			"reason_code": InternalDetail("lua_error"),
		}))
	}

	return CheckResult{
		Err:          r.Err,
		Status:       statusFromError(r.Err),
		Matched:      r.Action,
		DecisionHint: filterDecision(r),
		Reason:       reasonFromError(r.Err),
		Duration:     r.Duration,
		Attributes:   attributes,
	}
}

func (k ScriptKind) policySegment() string {
	switch k {
	case ScriptKindFilter:
		return "filter"
	default:
		return "control"
	}
}

func statusMessageDetails(message string) map[string]DetailValue {
	if message == "" {
		return nil
	}

	return map[string]DetailValue{
		"status_message": PublicMessageDetail(message),
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

func controlDecision(result ScriptResult) policy.Decision {
	if result.Err != nil {
		return policy.DecisionTempFail
	}

	if result.Triggered {
		return policy.DecisionDeny
	}

	return policy.DecisionNeutral
}

func filterDecision(result ScriptResult) policy.Decision {
	if result.Err != nil {
		return policy.DecisionTempFail
	}

	if result.Action {
		return policy.DecisionDeny
	}

	return policy.DecisionNeutral
}
