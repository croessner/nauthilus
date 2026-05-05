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

// Package report contains redaction-aware policy decision report primitives.
package report

import "github.com/croessner/nauthilus/server/policy"

// RedactedValue is the placeholder used for unsafe report values.
const RedactedValue = "[redacted]"

// Sensitivity describes whether a detail may appear in sanitized reports.
type Sensitivity string

const (
	// SensitivityPublic marks values safe for selected public output.
	SensitivityPublic Sensitivity = "public"

	// SensitivityInternal marks internal diagnostic values.
	SensitivityInternal Sensitivity = "internal"

	// SensitivitySecret marks secret values that must never be exposed.
	SensitivitySecret Sensitivity = "secret"
)

// DetailPurpose describes special handling for an attribute detail.
type DetailPurpose string

// PurposeResponseMessage marks a detail that may feed a selected response message.
const PurposeResponseMessage DetailPurpose = "response_message"

// DetailValue is a runtime value for one attribute detail.
type DetailValue struct {
	Value       any           `json:"value,omitempty"`
	Sensitivity Sensitivity   `json:"-"`
	Purpose     DetailPurpose `json:"-"`
	Selected    bool          `json:"-"`
}

// AttributeValue is a request-time policy attribute emission.
type AttributeValue struct {
	ID        string                 `json:"id"`
	Stage     policy.Stage           `json:"stage"`
	Operation policy.Operation       `json:"operation,omitempty"`
	Value     any                    `json:"value,omitempty"`
	Details   map[string]DetailValue `json:"details,omitempty"`
}

// CheckResult is the report-facing shape for a collected check.
type CheckResult struct {
	Name         string             `json:"name"`
	Type         string             `json:"type,omitempty"`
	Reason       string             `json:"reason,omitempty"`
	Operation    policy.Operation   `json:"operation,omitempty"`
	Stage        policy.Stage       `json:"stage"`
	Status       policy.CheckStatus `json:"status"`
	DecisionHint policy.Decision    `json:"decision_hint,omitempty"`
	Matched      bool               `json:"matched,omitempty"`
	Attributes   []string           `json:"attributes,omitempty"`
}

// UnavailableFact records a fact source that was intentionally not executed.
type UnavailableFact struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// PolicyDecision is the report-facing shape for one selected policy rule.
type PolicyDecision struct {
	ResponseMessage *ResponseMessageSelection `json:"response_message,omitempty"`
	Control         *DecisionControl          `json:"control,omitempty"`
	Name            string                    `json:"policy_name"`
	Reason          string                    `json:"reason,omitempty"`
	OutcomeMarker   string                    `json:"outcome_marker,omitempty"`
	ResponseMarker  string                    `json:"response_marker,omitempty"`
	FSMEventMarker  string                    `json:"fsm_event_marker,omitempty"`
	Stage           policy.Stage              `json:"stage"`
	Effect          policy.Decision           `json:"effect"`
	Obligations     []EffectRequest           `json:"obligations,omitempty"`
	Advice          []EffectRequest           `json:"advice,omitempty"`
}

// FinalDecision is the report-facing final policy decision.
type FinalDecision struct {
	ResponseMessage *ResponseMessageSelection `json:"response_message,omitempty"`
	Control         *DecisionControl          `json:"control,omitempty"`
	PolicyName      string                    `json:"policy_name,omitempty"`
	Reason          string                    `json:"reason,omitempty"`
	OutcomeMarker   string                    `json:"outcome_marker,omitempty"`
	ResponseMarker  string                    `json:"response_marker,omitempty"`
	FSMEventMarker  string                    `json:"fsm_event_marker,omitempty"`
	Stage           policy.Stage              `json:"stage,omitempty"`
	Effect          policy.Decision           `json:"effect"`
	Obligations     []EffectRequest           `json:"obligations,omitempty"`
	Advice          []EffectRequest           `json:"advice,omitempty"`
}

// ResponseMessageSelection describes the selected client-visible message.
type ResponseMessageSelection struct {
	Source       string `json:"source,omitempty"`
	Message      string `json:"message,omitempty"`
	AttributeID  string `json:"attribute,omitempty"`
	Detail       string `json:"detail,omitempty"`
	Fallback     string `json:"fallback,omitempty"`
	FallbackUsed bool   `json:"fallback_used,omitempty"`
}

// EffectRequest describes a planned policy effect.
type EffectRequest struct {
	ID   string         `json:"id"`
	Args map[string]any `json:"args,omitempty"`
}

// DecisionControl describes stage-local control selected by policy.
type DecisionControl struct {
	SkipRemainingStageChecks bool `json:"skip_remaining_stage_checks,omitempty"`
}

// ObserveReport stores observe comparison output.
type ObserveReport struct {
	Production              *FinalDecision `json:"production,omitempty"`
	Shadow                  *FinalDecision `json:"shadow,omitempty"`
	Surface                 string         `json:"surface,omitempty"`
	MismatchType            string         `json:"mismatch_type,omitempty"`
	ProductionTerminalState string         `json:"production_terminal_state,omitempty"`
	ShadowTerminalState     string         `json:"shadow_terminal_state,omitempty"`
	Mismatch                bool           `json:"mismatch"`
	ResponseMessageMatch    bool           `json:"response_message_match"`
	ObligationsMatch        bool           `json:"obligations_match"`
}

// DecisionReport is the redaction-aware container for policy diagnostics.
type DecisionReport struct {
	SessionID     string                     `json:"session_id,omitempty"`
	Operation     policy.Operation           `json:"operation,omitempty"`
	Stage         policy.Stage               `json:"stage,omitempty"`
	Attributes    map[string]AttributeValue  `json:"attributes"`
	Checks        map[string]CheckResult     `json:"checks"`
	MissingChecks map[string]string          `json:"missing_checks,omitempty"`
	Unavailable   map[string]UnavailableFact `json:"unavailable,omitempty"`
	Policies      []PolicyDecision           `json:"policies"`
	Final         *FinalDecision             `json:"final,omitempty"`
	Observe       *ObserveReport             `json:"observe,omitempty"`
}

// NewDecisionReport returns an empty report with initialized collections.
func NewDecisionReport() *DecisionReport {
	return &DecisionReport{
		Attributes:    make(map[string]AttributeValue),
		Checks:        make(map[string]CheckResult),
		MissingChecks: make(map[string]string),
		Unavailable:   make(map[string]UnavailableFact),
		Policies:      make([]PolicyDecision, 0),
	}
}

// Redacted returns a report copy that is safe for normal diagnostics.
func (r *DecisionReport) Redacted() *DecisionReport {
	if r == nil {
		return NewDecisionReport()
	}

	redacted := &DecisionReport{
		SessionID:     r.SessionID,
		Operation:     r.Operation,
		Stage:         r.Stage,
		Attributes:    make(map[string]AttributeValue, len(r.Attributes)),
		Checks:        make(map[string]CheckResult, len(r.Checks)),
		MissingChecks: make(map[string]string, len(r.MissingChecks)),
		Unavailable:   make(map[string]UnavailableFact, len(r.Unavailable)),
		Policies:      clonePolicyDecisions(r.Policies),
		Final:         cloneFinalDecision(r.Final),
		Observe:       cloneObserveReport(r.Observe),
	}

	for id, attribute := range r.Attributes {
		redacted.Attributes[id] = attribute.Redacted()
	}

	for name, check := range r.Checks {
		redacted.Checks[name] = check
	}

	for name, reason := range r.MissingChecks {
		redacted.MissingChecks[name] = reason
	}

	for name, fact := range r.Unavailable {
		redacted.Unavailable[name] = fact
	}

	return redacted
}

func clonePolicyDecisions(decisions []PolicyDecision) []PolicyDecision {
	cloned := append([]PolicyDecision(nil), decisions...)
	for index := range cloned {
		cloned[index].ResponseMessage = cloneResponseMessage(cloned[index].ResponseMessage)
		cloned[index].Control = cloneDecisionControl(cloned[index].Control)
		cloned[index].Obligations = cloneEffectRequests(cloned[index].Obligations)
		cloned[index].Advice = cloneEffectRequests(cloned[index].Advice)
	}

	return cloned
}

func cloneFinalDecision(decision *FinalDecision) *FinalDecision {
	if decision == nil {
		return nil
	}

	cloned := *decision
	cloned.ResponseMessage = cloneResponseMessage(decision.ResponseMessage)
	cloned.Control = cloneDecisionControl(decision.Control)
	cloned.Obligations = cloneEffectRequests(decision.Obligations)
	cloned.Advice = cloneEffectRequests(decision.Advice)

	return &cloned
}

func cloneObserveReport(observe *ObserveReport) *ObserveReport {
	if observe == nil {
		return nil
	}

	cloned := *observe
	cloned.Production = cloneFinalDecision(observe.Production)
	cloned.Shadow = cloneFinalDecision(observe.Shadow)

	return &cloned
}

func cloneResponseMessage(message *ResponseMessageSelection) *ResponseMessageSelection {
	if message == nil {
		return nil
	}

	cloned := *message

	return &cloned
}

func cloneDecisionControl(control *DecisionControl) *DecisionControl {
	if control == nil {
		return nil
	}

	cloned := *control

	return &cloned
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

// Redacted returns an attribute copy with unsafe details removed or masked.
func (a AttributeValue) Redacted() AttributeValue {
	redacted := a
	if a.Details == nil {
		return redacted
	}

	redacted.Details = make(map[string]DetailValue, len(a.Details))
	for name, detail := range a.Details {
		redacted.Details[name] = detail.Redacted()
	}

	return redacted
}

// Redacted returns a detail copy that follows policy report safety rules.
func (d DetailValue) Redacted() DetailValue {
	if d.Sensitivity == SensitivityPublic && d.Selected {
		return d
	}

	redacted := d
	redacted.Value = RedactedValue

	return redacted
}
