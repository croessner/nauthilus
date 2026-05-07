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

// Package runtime contains policy snapshot activation primitives.
package runtime

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/server/policy"
	"github.com/croessner/nauthilus/server/policy/registry"
)

// ErrNilSnapshot is returned when activation receives no candidate snapshot.
var ErrNilSnapshot = errors.New("policy snapshot is nil")

// Snapshot is the immutable request-time policy runtime handle.
type Snapshot struct {
	CreatedAt          time.Time
	AttributeRegistry  map[string]registry.AttributeDefinition
	CheckTypeRegistry  map[string]CheckTypeDefinition
	ResponseRegistry   map[string]ResponseDefinition
	ObligationRegistry map[string]EffectDefinition
	AdviceRegistry     map[string]EffectDefinition
	FSMEventRegistry   map[string]FSMEventDefinition
	StagePlans         map[policy.Operation]map[policy.Stage]CompiledStagePlan
	Sets               CompiledSets
	RequestAttributes  RequestAttributeSettings
	Report             ReportSettings
	Mode               string
	DefaultPolicy      string
	Generation         uint64
}

// Clone returns a detached copy of the snapshot value.
func (s *Snapshot) Clone() *Snapshot {
	if s == nil {
		return nil
	}

	cloned := *s
	cloned.AttributeRegistry = cloneMap(s.AttributeRegistry, registry.CloneDefinition)
	cloned.CheckTypeRegistry = cloneMap(s.CheckTypeRegistry, cloneCheckTypeDefinition)
	cloned.ResponseRegistry = cloneMap(s.ResponseRegistry, cloneResponseDefinition)
	cloned.ObligationRegistry = cloneMap(s.ObligationRegistry, cloneEffectDefinition)
	cloned.AdviceRegistry = cloneMap(s.AdviceRegistry, cloneEffectDefinition)
	cloned.FSMEventRegistry = cloneMap(s.FSMEventRegistry, cloneFSMEventDefinition)
	cloned.StagePlans = cloneStagePlans(s.StagePlans)
	cloned.Sets = s.Sets.Clone()
	cloned.RequestAttributes = s.RequestAttributes.Clone()

	return &cloned
}

// CheckTypeDefinition describes one configured check type.
type CheckTypeDefinition struct {
	ConfigRefPrefix            string
	Stage                      policy.Stage
	Operations                 []policy.Operation
	MinimumAttributes          []string
	ObserveSafeDefault         bool
	AllowsObserveSafeAssertion bool
}

// FSMEventDefinition describes one registered FSM event marker.
type FSMEventDefinition struct {
	ID            string
	AllowedStage  policy.Stage
	PolicyVisible bool
}

// ResponseDefinition describes one response marker.
type ResponseDefinition struct {
	ID       string
	Effect   policy.Decision
	Profiles []string
}

// EffectDefinition describes one registered obligation or advice marker.
type EffectDefinition struct {
	ID   string
	Kind string
}

// ReportSettings is the compiled policy report toggle set.
type ReportSettings struct {
	Enabled           bool
	IncludeFSM        bool
	IncludeChecks     bool
	IncludeAttributes bool
}

// RequestAttributeSettings contains allowlisted request inputs exposed as policy facts.
type RequestAttributeSettings struct {
	Headers  []RequestHeaderAttribute
	Metadata []RequestMetadataAttribute
}

// Clone returns a detached copy of request attribute settings.
func (s RequestAttributeSettings) Clone() RequestAttributeSettings {
	return RequestAttributeSettings{
		Headers:  cloneRequestAttributePlans(s.Headers),
		Metadata: cloneRequestAttributePlans(s.Metadata),
	}
}

// RequestHeaderAttribute contains one HTTP header-to-policy-attribute plan.
type RequestHeaderAttribute struct {
	Normalize RequestAttributeNormalization
	Header    string
	Attribute string
}

// RequestMetadataAttribute contains one gRPC metadata-to-policy-attribute plan.
type RequestMetadataAttribute struct {
	Normalize RequestAttributeNormalization
	Key       string
	Attribute string
}

// RequestAttributeNormalization describes deterministic request value normalization.
type RequestAttributeNormalization struct {
	Trim      bool
	Case      string
	MaxLength int
}

// CompiledSets contains reusable typed policy operands.
type CompiledSets struct {
	Networks    map[string][]netip.Prefix
	TimeWindows map[string]CompiledTimeWindow
}

// Clone returns a detached copy of compiled sets.
func (s CompiledSets) Clone() CompiledSets {
	return CompiledSets{
		Networks:    cloneSliceMap(s.Networks),
		TimeWindows: cloneMap(s.TimeWindows, cloneTimeWindow),
	}
}

// CompiledTimeWindow contains a validated local-time window set.
type CompiledTimeWindow struct {
	LocationName string
	Days         []time.Weekday
	Intervals    []CompiledTimeInterval
}

// CompiledTimeInterval contains minute offsets in local time.
type CompiledTimeInterval struct {
	StartMinute int
	EndMinute   int
}

// CompiledStagePlan contains one operation/stage plan.
type CompiledStagePlan struct {
	Stage    policy.Stage
	Checks   []CompiledCheck
	Policies []CompiledPolicy
}

// CompiledCheck contains a validated check plan entry.
type CompiledCheck struct {
	RunIf       RunIfPlan
	Name        string
	Type        string
	ConfigRef   string
	Output      string
	Stage       policy.Stage
	Operations  []policy.Operation
	After       []string
	ObserveSafe bool
}

// RunIfPlan contains the compiled structural scheduler guard.
type RunIfPlan struct {
	AuthState string
}

// CompiledPolicy contains a validated policy rule.
type CompiledPolicy struct {
	Then          DecisionPlan
	Root          CompiledExpr
	Name          string
	Stage         policy.Stage
	Operations    []policy.Operation
	RequireChecks []string
}

// ExprKind identifies the compiled condition node shape.
type ExprKind string

const (
	// ExprKindAttribute identifies an attribute comparison.
	ExprKindAttribute ExprKind = "attribute"

	// ExprKindAll identifies a logical all node.
	ExprKindAll ExprKind = "all"

	// ExprKindAny identifies a logical any node.
	ExprKindAny ExprKind = "any"

	// ExprKindNot identifies a logical not node.
	ExprKindNot ExprKind = "not"

	// ExprKindAlways identifies an unconditional match.
	ExprKindAlways ExprKind = "always"
)

// Operator identifies a compiled attribute operator.
type Operator string

// CompiledExpr is a typed policy condition node.
type CompiledExpr struct {
	Expected    TypedValue
	Kind        ExprKind
	AttributeID string
	Detail      string
	Operator    Operator
	ValueType   registry.AttributeType
	Children    []CompiledExpr
}

// TypedValue is a request-time-ready policy operand.
type TypedValue struct {
	Value any
}

// DecisionPlan contains validated decision output.
type DecisionPlan struct {
	ResponseMessage  ResponseMessagePlan
	ResponseLanguage ResponseLanguagePlan
	Control          DecisionControl
	Decision         policy.Decision
	Reason           string
	OutcomeMarker    string
	FSMEventMarker   string
	ResponseMarker   string
	Obligations      []EffectRequest
	Advice           []EffectRequest
}

// ResponseMessagePlan contains a validated response-message source.
type ResponseMessagePlan struct {
	Source      string
	Literal     string
	I18NKey     string
	AttributeID string
	Detail      string
	Fallback    string
	MaxLength   int
}

// ResponseLanguagePlan contains validated response-language metadata.
type ResponseLanguagePlan struct {
	Source      string
	Language    string
	AttributeID string
	Fallback    string
}

// EffectRequest contains one compiled obligation or advice reference.
type EffectRequest struct {
	ID   string
	Args map[string]any
}

// DecisionControl contains stage-local decision controls.
type DecisionControl struct {
	SkipRemainingStageChecks bool
}

// SnapshotStore publishes complete snapshots atomically.
type SnapshotStore struct {
	active atomic.Pointer[Snapshot]
}

// NewSnapshotStore returns a store initialized with the provided snapshot.
func NewSnapshotStore(initial *Snapshot) *SnapshotStore {
	store := &SnapshotStore{}
	if initial != nil {
		store.active.Store(initial.Clone())
	}

	return store
}

// Active returns the currently active snapshot.
func (s *SnapshotStore) Active() *Snapshot {
	return s.active.Load().Clone()
}

// Activate publishes a complete candidate snapshot.
func (s *SnapshotStore) Activate(candidate *Snapshot) error {
	if candidate == nil {
		return ErrNilSnapshot
	}

	s.active.Store(candidate.Clone())

	return nil
}

func cloneMap[T any](input map[string]T, cloneValue func(T) T) map[string]T {
	if input == nil {
		return nil
	}

	output := make(map[string]T, len(input))
	for key, value := range input {
		output[key] = cloneValue(value)
	}

	return output
}

func cloneSliceMap[T any](input map[string][]T) map[string][]T {
	if input == nil {
		return nil
	}

	output := make(map[string][]T, len(input))
	for key, values := range input {
		output[key] = append([]T(nil), values...)
	}

	return output
}

func cloneRequestAttributePlans[T RequestHeaderAttribute | RequestMetadataAttribute](input []T) []T {
	return append([]T(nil), input...)
}

func cloneCheckTypeDefinition(definition CheckTypeDefinition) CheckTypeDefinition {
	definition.Operations = append([]policy.Operation(nil), definition.Operations...)
	definition.MinimumAttributes = append([]string(nil), definition.MinimumAttributes...)

	return definition
}

func cloneResponseDefinition(definition ResponseDefinition) ResponseDefinition {
	definition.Profiles = append([]string(nil), definition.Profiles...)

	return definition
}

func cloneEffectDefinition(definition EffectDefinition) EffectDefinition {
	return definition
}

func cloneFSMEventDefinition(definition FSMEventDefinition) FSMEventDefinition {
	return definition
}

func cloneTimeWindow(window CompiledTimeWindow) CompiledTimeWindow {
	window.Days = append([]time.Weekday(nil), window.Days...)
	window.Intervals = append([]CompiledTimeInterval(nil), window.Intervals...)

	return window
}

func cloneStagePlans(input map[policy.Operation]map[policy.Stage]CompiledStagePlan) map[policy.Operation]map[policy.Stage]CompiledStagePlan {
	if input == nil {
		return nil
	}

	output := make(map[policy.Operation]map[policy.Stage]CompiledStagePlan, len(input))
	for operation, stagePlans := range input {
		output[operation] = cloneStageMap(stagePlans)
	}

	return output
}

func cloneStageMap(input map[policy.Stage]CompiledStagePlan) map[policy.Stage]CompiledStagePlan {
	if input == nil {
		return nil
	}

	output := make(map[policy.Stage]CompiledStagePlan, len(input))
	for stage, plan := range input {
		output[stage] = cloneStagePlan(plan)
	}

	return output
}

func cloneStagePlan(plan CompiledStagePlan) CompiledStagePlan {
	plan.Checks = append([]CompiledCheck(nil), plan.Checks...)
	for index := range plan.Checks {
		plan.Checks[index].Operations = append([]policy.Operation(nil), plan.Checks[index].Operations...)
		plan.Checks[index].After = append([]string(nil), plan.Checks[index].After...)
	}

	plan.Policies = append([]CompiledPolicy(nil), plan.Policies...)
	for index := range plan.Policies {
		plan.Policies[index] = clonePolicy(plan.Policies[index])
	}

	return plan
}

func clonePolicy(compiled CompiledPolicy) CompiledPolicy {
	compiled.Operations = append([]policy.Operation(nil), compiled.Operations...)
	compiled.RequireChecks = append([]string(nil), compiled.RequireChecks...)
	compiled.Root = cloneExpr(compiled.Root)
	compiled.Then.Obligations = cloneEffectRequests(compiled.Then.Obligations)
	compiled.Then.Advice = cloneEffectRequests(compiled.Then.Advice)

	return compiled
}

func cloneExpr(expr CompiledExpr) CompiledExpr {
	expr.Children = append([]CompiledExpr(nil), expr.Children...)
	for index := range expr.Children {
		expr.Children[index] = cloneExpr(expr.Children[index])
	}

	return expr
}

func cloneEffectRequests(requests []EffectRequest) []EffectRequest {
	cloned := append([]EffectRequest(nil), requests...)
	for index := range cloned {
		if cloned[index].Args == nil {
			continue
		}

		args := make(map[string]any, len(cloned[index].Args))
		for key, value := range cloned[index].Args {
			args[key] = value
		}

		cloned[index].Args = args
	}

	return cloned
}
