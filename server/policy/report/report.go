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
	Name   string             `json:"name"`
	Stage  policy.Stage       `json:"stage"`
	Status policy.CheckStatus `json:"status"`
}

// PolicyDecision is the report-facing shape for one selected policy rule.
type PolicyDecision struct {
	Name           string          `json:"policy_name"`
	Stage          policy.Stage    `json:"stage"`
	Effect         policy.Decision `json:"effect"`
	ResponseMarker string          `json:"response_marker,omitempty"`
	FSMEventMarker string          `json:"fsm_event_marker,omitempty"`
}

// FinalDecision is the report-facing final policy decision.
type FinalDecision struct {
	Effect         policy.Decision `json:"effect"`
	ResponseMarker string          `json:"response_marker,omitempty"`
	FSMEventMarker string          `json:"fsm_event_marker,omitempty"`
}

// ObserveReport is reserved for later default-vs-custom comparison output.
type ObserveReport struct {
	Mismatch bool `json:"mismatch"`
}

// DecisionReport is the redaction-aware container for policy diagnostics.
type DecisionReport struct {
	SessionID  string                    `json:"session_id,omitempty"`
	Operation  policy.Operation          `json:"operation,omitempty"`
	Stage      policy.Stage              `json:"stage,omitempty"`
	Attributes map[string]AttributeValue `json:"attributes"`
	Checks     map[string]CheckResult    `json:"checks"`
	Policies   []PolicyDecision          `json:"policies"`
	Final      *FinalDecision            `json:"final,omitempty"`
	Observe    *ObserveReport            `json:"observe,omitempty"`
}

// NewDecisionReport returns an empty report with initialized collections.
func NewDecisionReport() *DecisionReport {
	return &DecisionReport{
		Attributes: make(map[string]AttributeValue),
		Checks:     make(map[string]CheckResult),
		Policies:   make([]PolicyDecision, 0),
	}
}

// Redacted returns a report copy that is safe for normal diagnostics.
func (r *DecisionReport) Redacted() *DecisionReport {
	if r == nil {
		return NewDecisionReport()
	}

	redacted := &DecisionReport{
		SessionID:  r.SessionID,
		Operation:  r.Operation,
		Stage:      r.Stage,
		Attributes: make(map[string]AttributeValue, len(r.Attributes)),
		Checks:     make(map[string]CheckResult, len(r.Checks)),
		Policies:   append([]PolicyDecision(nil), r.Policies...),
		Final:      r.Final,
		Observe:    r.Observe,
	}

	for id, attribute := range r.Attributes {
		redacted.Attributes[id] = attribute.Redacted()
	}

	for name, check := range r.Checks {
		redacted.Checks[name] = check
	}

	return redacted
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
