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

package supporthistory

import (
	"time"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// Reputation evidence states.
const (
	reputationRecorded     = "recorded"
	reputationNoneRecorded = "none_recorded"
	reputationLegacy       = "legacy_not_projected"
)

// optional returns nil for an empty string so absent values never read as empty claims.
func optional(value string) *string {
	if value == "" {
		return nil
	}

	return &value
}

// recorded returns a recorded free-text value complete for a support answer, or nil when it is empty. Recorded values
// can carry text a client typed; they leave the host verbatim as data (see supportaccess.VerbatimText).
func recorded(value string) *string {
	return optional(recordedText(value))
}

// recordedText returns a recorded free-text value complete, with invisible format characters made visible.
func recordedText(value string) string {
	return supportaccess.VerbatimText(value)
}

// stringValue dereferences an optional string.
func stringValue(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

// eventIdentity projects the recorded identity claims of an event and whether they match the subject.
func eventIdentity(matched bool, by string, login, account string, found *bool) EventIdentity {
	return EventIdentity{SubjectMatch: matched, MatchedBy: optional(by), SuppliedLogin: recorded(login),
		CanonicalAccount: recorded(account), AccountFound: found}
}

// projectLogin interprets and projects one login row.
func projectLogin(record LoginRecord, input attemptInput) projectedEvent {
	reading := interpretLogin(record, input.key.Kind)
	matched, by := input.matcher.identityOfLogin(record)

	event := Event{
		OccurredAt: record.At.UTC(), EventID: recorded(record.EventID), Source: sourceNameLogins,
		RequestID: recordedText(record.Session), Instance: recordedText(record.Instance), Stage: reading.stage, Result: reading.result,
		Code: reading.code, Category: reading.category, RecordVersion: record.ContractVersion,
		Method:   recorded(record.Method),
		Identity: eventIdentity(matched, by, record.Username, record.Account, record.UserFound),
		Context: EventContext{ClientIP: recorded(record.ClientIP), Protocol: recorded(record.Protocol),
			Service: recorded(record.Service), OIDCClientID: recorded(record.OIDCClientID),
			SAMLEntityID: recorded(record.SAMLEntityID), GrantType: recorded(record.GrantType),
			Transport: recorded(record.Transport), TransportStatus: record.TransportStatus},
	}

	if record.ContractVersion >= 1 {
		event.Decision = decisionOf(record)
	}

	event.Reputation = reputationOf(record)

	return projectedEvent{event: event, reading: reading, key: loginPosition(record)}
}

// decisionOf copies the recorded Policy result of a contract row including its answered status.
func decisionOf(record LoginRecord) *Decision {
	sources := append([]string{}, record.DecisionSources...)
	code, message := answeredStatusOf(record)

	return &Decision{
		Operation: record.Operation, Outcome: record.Outcome, OutcomeStage: record.OutcomeStage,
		OutcomeMarker: record.OutcomeMarker, ResponseMarker: record.ResponseMarker, PolicyRule: recordedText(record.PolicyRule),
		TempFailReason: recordedText(record.TempFailReason), TempFailCheckpoint: record.TempFailCheckpoint,
		PolicyStatus: record.PolicyStatus, FSMState: record.FSMState, DecisionSources: sources,
		BruteForceBucket: recorded(record.BruteForceBucket), BruteForceTolerated: record.BruteForceTolerated,
		AnsweredStatusCode: code, AnsweredStatusMessage: message,
	}
}

// answeredStatusOf returns the stored answered status of a sealed terminal decision. Without a sealed decision
// (contract §4.3: outcome unknown writes 0 and an empty text) both stay null, so no default can read as success.
func answeredStatusOf(record LoginRecord) (*int, *string) {
	switch record.Outcome {
	case outcomeOK, outcomeFail, outcomeTempfail:
	default:
		return nil, nil
	}

	var code *int

	if record.AnsweredStatusCode > 0 {
		value := record.AnsweredStatusCode
		code = &value
	}

	return code, recorded(record.AnsweredStatusMessage)
}

// reputationOf reports structured reputation evidence; an empty projection is "none recorded", never neutral,
// because an early rejection can end before any reputation check (contract §6).
func reputationOf(record LoginRecord) *Reputation {
	if record.ContractVersion < 1 {
		return &Reputation{State: reputationLegacy, Assessments: []ReputationAssessment{}}
	}

	if len(record.Reputation) == 0 {
		return &Reputation{State: reputationNoneRecorded, Assessments: []ReputationAssessment{},
			Truncated: record.ReputationTruncated}
	}

	return &Reputation{State: reputationRecorded, Truncated: record.ReputationTruncated,
		Assessments: append([]ReputationAssessment{}, record.Reputation...)}
}

// projectAuthEvent interprets and projects one step event; only second-factor events carry a factor block.
func projectAuthEvent(record AuthEventRecord, input attemptInput) projectedEvent {
	reading := interpretAuthEvent(record)
	matched, by := input.matcher.identityOfEvent(record)
	role := record.FactorRole

	event := Event{
		OccurredAt: record.At.UTC(), EventID: recorded(record.EventID), Source: sourceNameAuthEvents,
		RequestID: recordedText(record.RequestID), Instance: recordedText(record.Instance), Stage: reading.stage, Result: reading.result,
		Code: reading.code, Category: reading.category, RecordVersion: record.EventVersion,
		FactorRole: optional(role), Method: recorded(record.Method),
		Identity: eventIdentity(matched, by, "", record.Account, nil),
		Context: EventContext{ClientIP: recorded(record.ClientIP), Protocol: recorded(record.Protocol),
			OIDCClientID: recorded(record.ClientID), SAMLEntityID: recorded(record.SAMLEntityID)},
	}

	if record.EventType == eventTypeMFA {
		event.Factor = &Factor{Result: record.Result, Reason: record.Reason, FlowEffect: record.FlowEffect,
			FailLatched: record.FailLatched}
	}

	return projectedEvent{event: event, reading: reading, key: authEventPosition(record)}
}

// timePointer returns a pointer to a copy of a time value.
func timePointer(value time.Time) *time.Time {
	return &value
}
