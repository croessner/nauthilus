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

	"github.com/croessner/nauthilus/v4/server/policy"
)

// ScriptKind identifies the callback family observed by the host adapter.
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

// ScriptRecorder consumes per-script Lua results.
type ScriptRecorder interface {
	RecordScriptResult(context.Context, ScriptResult)
}

// ScriptSink records callback results without owning policy execution order.
type ScriptSink struct {
	ctx *DecisionContext
}

// NewScriptSink creates a Lua script result sink for the decision context.
func NewScriptSink(ctx *DecisionContext) *ScriptSink {
	return &ScriptSink{ctx: ctx}
}

// RecordScriptResult converts one Lua callback result into host observations.
func (s *ScriptSink) RecordScriptResult(ctx context.Context, result ScriptResult) {
	if s == nil || s.ctx == nil || strings.TrimSpace(result.Name) == "" {
		return
	}

	check := s.ctx.BeginCheck(ctx, result.selector())
	check.Finish(result.checkResult(s.ctx.Report().Operation))
}

// selector names the callback observation without a configuration reference.
func (r ScriptResult) selector() CheckSelector {
	if r.Kind == ScriptKindSubject {
		return CheckSelector{
			CheckType: policy.CheckTypeLuaSubjectSource,
			Stage:     policy.StageSubjectAnalysis,
			Name:      "lua_subject_" + r.Name,
		}
	}

	return CheckSelector{
		CheckType: policy.CheckTypeLuaEnvironment,
		Stage:     policy.StagePreAuth,
		Name:      "lua_environment_" + r.Name,
	}
}

// checkResult maps one callback family to its stable observation shape.
func (r ScriptResult) checkResult(operation policy.Operation) CheckResult {
	if r.Kind == ScriptKindSubject {
		return r.subjectResult(operation)
	}

	return r.environmentResult(operation)
}

// environmentResult maps an environment callback into pre-auth observations.
func (r ScriptResult) environmentResult(operation policy.Operation) CheckResult {
	attributes := []AttributeValue{
		BoolAttribute(
			scriptAttributeID(r.Kind, r.Name, "triggered"),
			policy.StagePreAuth,
			operation,
			r.Triggered,
			statusMessageDetails(r.StatusMessage),
		),
		BoolAttribute(
			scriptAttributeID(r.Kind, r.Name, "abort"),
			policy.StagePreAuth,
			operation,
			r.Abort,
			nil,
		),
	}

	if r.Err != nil {
		attributes = append(attributes, BoolAttribute(
			scriptAttributeID(r.Kind, r.Name, "error"),
			policy.StagePreAuth,
			operation,
			true,
			map[string]DetailValue{scriptDetailReasonCode: InternalDetail(scriptReasonLuaError)},
		))
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

// subjectResult maps a subject callback into subject observations.
func (r ScriptResult) subjectResult(operation policy.Operation) CheckResult {
	attributes := []AttributeValue{
		BoolAttribute(
			scriptAttributeID(r.Kind, r.Name, "rejected"),
			policy.StageSubjectAnalysis,
			operation,
			r.Action,
			statusMessageDetails(r.StatusMessage),
		),
	}

	if r.Err != nil {
		attributes = append(attributes, BoolAttribute(
			scriptAttributeID(r.Kind, r.Name, "error"),
			policy.StageSubjectAnalysis,
			operation,
			true,
			map[string]DetailValue{scriptDetailReasonCode: InternalDetail(scriptReasonLuaError)},
		))
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

// policySegment returns the stable callback observation namespace.
func (k ScriptKind) policySegment() string {
	if k == ScriptKindSubject {
		return "subject"
	}

	return "environment"
}

// statusMessageDetails converts a non-empty status message into public metadata.
func statusMessageDetails(message string) map[string]DetailValue {
	if message == "" {
		return nil
	}

	return map[string]DetailValue{
		scriptDetailStatusMessage: PublicMessageDetail(message),
	}
}

// statusFromError maps callback failures to the stable check status.
func statusFromError(err error) policy.CheckStatus {
	if err != nil {
		return policy.CheckStatusError
	}

	return policy.CheckStatusOK
}

// reasonFromError maps callback failures to the stable diagnostic code.
func reasonFromError(err error) string {
	if err != nil {
		return scriptReasonLuaError
	}

	return ""
}

// environmentDecision maps one environment result to bounded host diagnostics.
func environmentDecision(result ScriptResult) policy.Decision {
	if result.Err != nil {
		return policy.DecisionTempFail
	}

	if result.Triggered {
		return policy.DecisionDeny
	}

	return policy.DecisionNeutral
}

// subjectDecision maps one subject result to bounded host diagnostics.
func subjectDecision(result ScriptResult) policy.Decision {
	if result.Err != nil {
		return policy.DecisionTempFail
	}

	if result.Action {
		return policy.DecisionDeny
	}

	return policy.DecisionNeutral
}
