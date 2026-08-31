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

// Package collection records request-local authentication observations.
package collection

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	monittrace "github.com/croessner/nauthilus/v4/server/monitoring/trace"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/observability"
	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"
	"github.com/croessner/nauthilus/v4/server/policy/report"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// AttributeValue is the request-time policy attribute value shape.
type AttributeValue = report.AttributeValue

// DetailValue is the request-time policy attribute detail shape.
type DetailValue = report.DetailValue

// CheckResult is the internal result produced by one mechanism adapter.
type CheckResult struct {
	Err          error
	Attributes   []AttributeValue
	Tags         []string
	Duration     time.Duration
	Reason       string
	Outcome      string
	Status       policy.CheckStatus
	DecisionHint policy.Decision
	Matched      bool
}

// CheckSelector names one host observation without selecting policy execution.
type CheckSelector struct {
	CheckType string
	Stage     policy.Stage
	Name      string
}

// DecisionContext stores request-local facts collected by authentication host adapters.
type DecisionContext struct {
	recorder    observability.Recorder
	report      *report.DecisionReport
	tracer      monittrace.Tracer
	definitions map[string]policyregistry.AttributeDefinition
	mu          sync.Mutex
	generation  uint64
}

// NewDecisionContext creates a request-local observation context from builtin host contracts.
func NewDecisionContext(
	operation policy.Operation,
	recorder observability.Recorder,
	generation uint64,
) *DecisionContext {
	policyReport := report.NewDecisionReport()
	policyReport.Operation = operation

	return &DecisionContext{
		recorder:    observability.SafeRecorder(recorder),
		report:      policyReport,
		tracer:      observability.NewTracer(),
		definitions: builtinDefinitions(),
		generation:  generation,
	}
}

// builtinDefinitions returns the immutable Go-owned host fact contract.
func builtinDefinitions() map[string]policyregistry.AttributeDefinition {
	registry, err := policyregistry.NewBuiltinAttributeRegistry()
	if err != nil {
		panic(fmt.Sprintf("build builtin policy attribute registry: %v", err))
	}

	return registry.Snapshot()
}

// Report returns the mutable request report owned by this context.
func (c *DecisionContext) Report() *report.DecisionReport {
	if c == nil || c.report == nil {
		return report.NewDecisionReport()
	}

	return c.report
}

// GenerationID returns the generation captured with this request-local context.
func (c *DecisionContext) GenerationID() uint64 {
	if c == nil {
		return 0
	}

	return c.generation
}

// AttributeDefinition returns one detached builtin host definition.
func (c *DecisionContext) AttributeDefinition(id string) (policyregistry.AttributeDefinition, bool) {
	if c == nil {
		return policyregistry.AttributeDefinition{}, false
	}

	definition, ok := c.definitions[id]
	if !ok {
		return policyregistry.AttributeDefinition{}, false
	}

	return policyregistry.CloneDefinition(definition), true
}

// AddAuthnPolicyAttributes installs exact generation-owned extension definitions before host execution.
func (c *DecisionContext) AddAuthnPolicyAttributes(
	definitions map[string]policyregistry.AttributeDefinition,
) error {
	if c == nil {
		return fmt.Errorf("policy decision context is unavailable")
	}

	detached := make(map[string]policyregistry.AttributeDefinition, len(definitions))
	for id, definition := range definitions {
		if strings.TrimSpace(id) == "" || definition.ID != id {
			return fmt.Errorf("captured authn Policy attribute %q has invalid identity", id)
		}

		detached[id] = policyregistry.CloneDefinition(definition)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for id := range detached {
		if _, exists := c.definitions[id]; exists {
			return fmt.Errorf("captured authn Policy attribute %q is already registered", id)
		}
	}

	for id, definition := range detached {
		c.definitions[id] = definition
	}

	return nil
}

// AddAuthnLuaFactDeclarations atomically installs the exact registry-script facts captured by one generation.
func (c *DecisionContext) AddAuthnLuaFactDeclarations(
	declarations []policyregistry.AuthnLuaFactDeclaration,
) error {
	if c == nil {
		return fmt.Errorf("policy decision context is unavailable")
	}

	definitions := make(map[string]policyregistry.AttributeDefinition, len(declarations))
	for index, declaration := range declarations {
		definition, err := authnLuaFactAttributeDefinition(declaration)
		if err != nil {
			return fmt.Errorf("captured authn Lua fact declaration %d: %w", index, err)
		}

		if _, exists := definitions[definition.ID]; exists {
			return fmt.Errorf("duplicate captured authn Lua fact declaration %q", definition.ID)
		}

		definitions[definition.ID] = definition
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for id := range definitions {
		if _, exists := c.definitions[id]; exists {
			return fmt.Errorf("captured authn Lua fact declaration %q is already registered", id)
		}
	}

	for id, definition := range definitions {
		c.definitions[id] = policyregistry.CloneDefinition(definition)
	}

	return nil
}

// authnLuaFactAttributeDefinition converts one immutable declaration into the host emitter contract.
func authnLuaFactAttributeDefinition(
	declaration policyregistry.AuthnLuaFactDeclaration,
) (policyregistry.AttributeDefinition, error) {
	if strings.TrimSpace(declaration.ID()) == "" || declaration.DeclaredType() == "" {
		return policyregistry.AttributeDefinition{}, fmt.Errorf("declaration identity or type is unavailable")
	}

	category := policyregistry.AttributeCategory(declaration.Category())
	switch category {
	case policyregistry.AttributeCategoryEnvironment,
		policyregistry.AttributeCategorySubject,
		policyregistry.AttributeCategoryResource:
	default:
		return policyregistry.AttributeDefinition{}, fmt.Errorf("declaration %q has invalid category", declaration.ID())
	}

	return policyregistry.AttributeDefinition{
		ID:          declaration.ID(),
		Description: declaration.Description(),
		Stage:       declaration.Stage(),
		Operations:  declaration.Actions(),
		Category:    category,
		Type:        declaration.DeclaredType(),
		Source:      policyregistry.SourceLua,
		Details:     declaration.Details(),
	}, nil
}

// BeginCheck opens metric and tracing collection for one host adapter observation.
func (c *DecisionContext) BeginCheck(ctx context.Context, selector CheckSelector) *ActiveCheck {
	if c == nil || c.report == nil {
		return &ActiveCheck{}
	}

	check := observedCheckFromSelector(selector)
	spanCtx, span := c.tracer.Start(ctx, "policy.check",
		attribute.String("policy.operation", string(c.report.Operation)),
		attribute.String("policy.stage", string(check.stage)),
		attribute.String("policy.check", check.name),
		attribute.String("policy.check_type", check.checkType),
	)

	return &ActiveCheck{
		ctx:     spanCtx,
		parent:  c,
		check:   check,
		span:    span,
		started: time.Now(),
	}
}

// observedCheckFromSelector assigns a stable fallback name for host observations.
func observedCheckFromSelector(selector CheckSelector) observedCheck {
	name := strings.TrimSpace(selector.Name)
	if name == "" {
		name = selector.CheckType
	}

	return observedCheck{name: name, checkType: selector.CheckType, stage: selector.Stage}
}

// MarkUnavailable records a host fact source that could not produce an observation.
func (c *DecisionContext) MarkUnavailable(name string, reason string) {
	if c == nil || c.report == nil || strings.TrimSpace(name) == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.report.Unavailable == nil {
		c.report.Unavailable = make(map[string]report.UnavailableFact)
	}

	c.report.Unavailable[name] = report.UnavailableFact{Name: name, Reason: reason}
}

// RecordAttribute stores one emitted policy attribute.
func (c *DecisionContext) RecordAttribute(value AttributeValue) {
	if c == nil || c.report == nil || value.ID == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.recordAttributeLocked(value)
}

// RecordAttributes stores emitted policy attributes under one request-local lock.
func (c *DecisionContext) RecordAttributes(values []AttributeValue) {
	if c == nil || c.report == nil || len(values) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, value := range values {
		if value.ID != "" {
			c.recordAttributeLocked(value)
		}
	}
}

// recordAttributeLocked stores one observation while the context mutex is held.
func (c *DecisionContext) recordAttributeLocked(value AttributeValue) {
	if c.report.Attributes == nil {
		c.report.Attributes = make(map[string]report.AttributeValue)
	}

	c.report.Attributes[value.ID] = value
}

// recordCheck stores one completed host check and its emitted observations.
func (c *DecisionContext) recordCheck(result CheckResult, check observedCheck) {
	if c == nil || c.report == nil || check.name == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if result.Status == "" {
		result.Status = policy.CheckStatusOK
	}

	attributeIDs := make([]string, 0, len(result.Attributes))
	for _, value := range result.Attributes {
		if value.ID == "" {
			continue
		}

		attributeIDs = append(attributeIDs, value.ID)
		c.recordAttributeLocked(value)
	}

	c.report.Checks[check.name] = report.CheckResult{
		Name:         check.name,
		Type:         check.checkType,
		Reason:       result.Reason,
		Operation:    c.report.Operation,
		Stage:        check.stage,
		Status:       result.Status,
		DecisionHint: result.DecisionHint,
		Matched:      result.Matched,
		Attributes:   attributeIDs,
	}
}

type observedCheck struct {
	name      string
	checkType string
	stage     policy.Stage
}

// ActiveCheck tracks one running host observation.
type ActiveCheck struct {
	parent   *DecisionContext
	span     trace.Span
	check    observedCheck
	ctx      context.Context
	started  time.Time
	finished bool
}

// Finish stores the check result and records metrics.
func (a *ActiveCheck) Finish(result CheckResult) {
	if a == nil || a.finished {
		return
	}

	a.finished = true
	if a.parent == nil {
		return
	}

	duration := time.Since(a.started)
	if result.Duration > 0 {
		duration = result.Duration
	}

	if result.Status == "" {
		result.Status = policy.CheckStatusOK
	}

	if result.Err != nil {
		result.Status = policy.CheckStatusError
		if result.Reason == "" {
			result.Reason = "technical_error"
		}

		if a.span != nil {
			a.span.RecordError(result.Err)
		}
	}

	a.parent.recordCheck(result, a.check)
	a.parent.recorder.RecordCheck(a.ctx, observability.CheckMeasurement{
		Duration:   duration,
		Operation:  a.parent.report.Operation,
		Stage:      a.check.stage,
		Check:      a.check.name,
		CheckType:  a.check.checkType,
		Status:     result.Status,
		ReasonCode: result.Reason,
	})

	if a.span != nil {
		a.span.SetAttributes(
			attribute.String("policy.status", string(result.Status)),
			attribute.Bool("policy.matched", result.Matched),
		)
		a.span.End()
	}
}

// BoolAttribute creates a bool policy attribute value.
func BoolAttribute(
	id string,
	stage policy.Stage,
	operation policy.Operation,
	value bool,
	details map[string]DetailValue,
) AttributeValue {
	return AttributeValue{ID: id, Stage: stage, Operation: operation, Value: value, Details: details}
}

// NumberAttribute creates a numeric policy attribute value.
func NumberAttribute(
	id string,
	stage policy.Stage,
	operation policy.Operation,
	value float64,
	details map[string]DetailValue,
) AttributeValue {
	return AttributeValue{ID: id, Stage: stage, Operation: operation, Value: value, Details: details}
}

// StringListAttribute creates a string-list policy attribute value.
func StringListAttribute(
	id string,
	stage policy.Stage,
	operation policy.Operation,
	value []string,
	details map[string]DetailValue,
) AttributeValue {
	return AttributeValue{
		ID: id, Stage: stage, Operation: operation,
		Value: append([]string(nil), value...), Details: details,
	}
}

// StringAttribute creates a string policy attribute value.
func StringAttribute(id string, stage policy.Stage, operation policy.Operation, value string) AttributeValue {
	return AttributeValue{ID: id, Stage: stage, Operation: operation, Value: value}
}

// StringAttributeWithDetails creates a string policy attribute value with details.
func StringAttributeWithDetails(
	id string,
	stage policy.Stage,
	operation policy.Operation,
	value string,
	details map[string]DetailValue,
) AttributeValue {
	return AttributeValue{ID: id, Stage: stage, Operation: operation, Value: value, Details: details}
}

// TimeAttribute creates a timestamp policy attribute value.
func TimeAttribute(id string, stage policy.Stage, operation policy.Operation, value time.Time) AttributeValue {
	return AttributeValue{ID: id, Stage: stage, Operation: operation, Value: value}
}

// InternalDetail creates a redacted internal detail value.
func InternalDetail(value any) DetailValue {
	return DetailValue{Value: value, Sensitivity: report.SensitivityInternal}
}

// PublicMessageDetail creates a public response-message candidate detail.
func PublicMessageDetail(value string) DetailValue {
	return DetailValue{
		Value: value, Sensitivity: report.SensitivityPublic, Purpose: report.PurposeResponseMessage,
	}
}

// scriptAttributeID returns the stable callback observation identity.
func scriptAttributeID(kind ScriptKind, name string, suffix string) string {
	return fmt.Sprintf("auth.lua.%s.%s.%s", kind.policySegment(), name, suffix)
}
