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
	"context"
	"slices"
	"time"
)

// OIDC completion values (DIAGNOSTIC_CONTRACT.md §7.6).
const (
	completionScopeAuthorizationCode = "oidc_authorization_code"

	completionTokensIssued        = "tokens_issued"
	completionRedemptionRejected  = "redemption_rejected"
	completionRedemptionFailed    = "redemption_failed"
	completionRedemptionPending   = "redemption_pending"
	completionCodeExpired         = "code_expired_redemption_not_observed"
	completionIssuanceNotObserved = "code_issuance_not_observed"
	completionNotRecorded         = "not_recorded"
	completionUnknown             = "unknown"

	basisTokensIssued        = "oidc_tokens_issued"
	basisRedemptionRejected  = "oidc_code_redemption_rejected"
	basisRedemptionFailed    = "oidc_code_redemption_failed"
	progressCodeIssued       = "authorization_code_issued"
	progressTokensIssued     = "tokens_issued"
	stepSessionReused        = "session_reused"
	gapCompletionNotObserved = "FLOW_COMPLETION_NOT_OBSERVED"
	gapCompletionUndecidable = "FLOW_COMPLETION_SCOPE_UNDETERMINED"
)

// completionOutcomes maps the final completion states onto the attempt outcome and its basis. Every other state
// leaves the flow not_observed: a missing follow-up event proves neither an abort nor a timeout.
var completionOutcomes = map[string][2]string{
	completionTokensIssued:       {outcomeSucceeded, basisTokensIssued},
	completionRedemptionRejected: {outcomeRejected, basisRedemptionRejected},
	completionRedemptionFailed:   {outcomeTechnicalError, basisRedemptionFailed},
}

// completionCutover is the completion recording state of the deployment for one operation.
type completionCutover struct {
	since *time.Time
	known bool
}

// completionCutoverAt probes once per operation when the deployment started recording completion events.
func (s *Service) completionCutoverAt(ctx context.Context, until time.Time) completionCutover {
	since, known := s.attempts.CompletionEventsSince(ctx, until)
	if !known {
		since = nil
	}

	return completionCutover{since: since, known: known}
}

// completionEvidence is the OIDC authorization-code completion reading of one flow.
type completionEvidence struct {
	block       *Completion
	issuance    *AuthEventRecord
	recorded    bool
	scoped      bool
	oidc        bool
	grantKnown  bool
	conflicting bool
}

// splitStepEvents separates second-factor events from OIDC completion events; MFA-derived fields read only the first.
func splitStepEvents(records []AuthEventRecord) (factor, completion []AuthEventRecord) {
	for _, record := range records {
		if record.EventType == eventTypeCodeIssuance || record.EventType == eventTypeCodeRedemption {
			completion = append(completion, record)
		} else {
			factor = append(factor, record)
		}
	}

	return factor, completion
}

// evaluateCompletion reads the completion of one flow. Only authorization-code flows get a block: SAML, device-code,
// and flows whose grant was never recorded have no completion evidence by design, and a latched flow is decided by
// its latch (a block appears there only when completion events contradict it).
func evaluateCompletion(input attemptInput, logins []LoginRecord, factor, completion []AuthEventRecord, latched bool) completionEvidence {
	evidence := completionEvidence{recorded: completionRecordedAt(input.completionSince, logins, factor, completion),
		scoped: len(completion) > 0 || slices.ContainsFunc(logins, func(record LoginRecord) bool {
			return record.GrantType == grantAuthorizationCode
		}),
		oidc: slices.ContainsFunc(logins, func(record LoginRecord) bool { return record.OIDCClientID != "" }) ||
			slices.ContainsFunc(factor, func(record AuthEventRecord) bool { return record.Protocol == protocolOIDC }),
		grantKnown: slices.ContainsFunc(logins, func(record LoginRecord) bool { return record.GrantType != "" })}

	if input.key.Kind != AttemptFlow || !evidence.scoped || latched && len(completion) == 0 {
		return evidence
	}

	evidence.issuance = earliestIssuance(completion)
	block := &Completion{Scope: completionScopeAuthorizationCode, Authentication: authenticationUnobserved}

	if evidence.issuance != nil {
		block.CodeIssuedAt = timePointer(evidence.issuance.At.UTC())
		block.Authentication = issuanceAuthentication(evidence.issuance.Reason)

		if lifetime, ok := CodeLifetimeOfIssuanceVersion(evidence.issuance.EventVersion); ok {
			block.CodeRedeemableUntil = timePointer(evidence.issuance.At.Add(lifetime).UTC())
		}
	}

	block.State, block.RedemptionObservedAt, evidence.conflicting = completionState(input, completion, block,
		evidence.recorded)
	evidence.block = block

	return evidence
}

// completionRecordedAt reports whether the deployment already recorded completion events when the flow began; older
// flows stay "never recorded" and are never upgraded by later recording.
func completionRecordedAt(since *time.Time, logins []LoginRecord, factor, completion []AuthEventRecord) bool {
	if since == nil {
		return false
	}

	var earliest time.Time

	observe := func(at time.Time) {
		if earliest.IsZero() || at.Before(earliest) {
			earliest = at
		}
	}

	for _, record := range logins {
		observe(record.At)
	}

	for _, record := range append(slices.Clone(factor), completion...) {
		observe(record.At)
	}

	return !earliest.IsZero() && !since.After(earliest)
}

// issuanceAuthentication maps the recorded issuance reason onto the completion authentication; an unknown value is
// never passed through.
func issuanceAuthentication(reason string) string {
	switch reason {
	case reasonAuthenticatedInFlow, reasonExistingSession, reasonSourceNotRecorded:
		return reason
	default:
		return authenticationUnobserved
	}
}

// earliestIssuance returns the first issuance event; one flow issues at most one code.
func earliestIssuance(completion []AuthEventRecord) *AuthEventRecord {
	var issuance *AuthEventRecord

	for index := range completion {
		record := &completion[index]
		if record.EventType == eventTypeCodeIssuance && (issuance == nil || record.At.Before(issuance.At)) {
			issuance = record
		}
	}

	return issuance
}

// completionState decides the completion state independent of row order: a successful redemption dominates every
// other event (a code is consumed once, so no later failure can undo it); a recorded failure is final; without a
// redemption the state separates pending, provably expired, not observed, never recorded, and unknown.
func completionState(input attemptInput, completion []AuthEventRecord, block *Completion, recorded bool) (string, *time.Time, bool) {
	redemption := readRedemptions(completion)
	if redemption.state != "" {
		return redemption.state, redemption.at, redemption.conflicting
	}

	switch {
	case redemption.unclassified || !input.eventsRead || input.read.limitHit:
		return completionUnknown, nil, false
	case block.CodeIssuedAt != nil:
		return redemptionWait(input, block), nil, false
	case recorded:
		return completionIssuanceNotObserved, nil, false
	default:
		return completionNotRecorded, nil, false
	}
}

// redemptionReading is the decided redemption of one flow; an empty state means no redemption decided it.
type redemptionReading struct {
	at           *time.Time
	state        string
	conflicting  bool
	unclassified bool
}

// readRedemptions folds the completion events into the deciding redemption: any success wins; otherwise one kind of
// failure decides, and disagreeing failures are conflicting and unknown.
func readRedemptions(completion []AuthEventRecord) redemptionReading {
	failures := map[string]*time.Time{}
	reading := redemptionReading{}

	for _, record := range completion {
		interpreted := interpretCompletionEvent(record)

		switch {
		case interpreted.code == CodeTokensIssued:
			return redemptionReading{state: completionTokensIssued, at: timePointer(record.At.UTC())}
		case interpreted.stage == stageTokenExchange && interpreted.result == resultRejected:
			failures[completionRedemptionRejected] = timePointer(record.At.UTC())
		case interpreted.stage == stageTokenExchange && interpreted.result == resultTechnicalError:
			failures[completionRedemptionFailed] = timePointer(record.At.UTC())
		case interpreted.category == categoryUnknown:
			reading.unclassified = true
		}
	}

	if len(failures) > 1 {
		return redemptionReading{state: completionUnknown, conflicting: true}
	}

	for state, at := range failures {
		reading.state, reading.at = state, at
	}

	return reading
}

// redemptionWait separates a code that may still be redeemed (or whose redemption may still be exported) from one
// that provably cannot be redeemed anymore. The expiry is stated only when the read range covers the whole
// redemption horizon; it never proves that no redemption happened, because an event can be dropped.
func redemptionWait(input attemptInput, block *Completion) string {
	if block.CodeRedeemableUntil == nil {
		return completionUnknown
	}

	horizon := block.CodeRedeemableUntil.Add(lateEventHorizon)

	switch {
	case input.queriedAt.Before(horizon):
		return completionRedemptionPending
	case input.read.openEnd || !input.read.until.Before(horizon):
		return completionCodeExpired
	default:
		return completionUnknown
	}
}

// outcome returns the attempt outcome a final completion state proves.
func (e completionEvidence) outcome() (string, string, bool) {
	if e.block == nil {
		return "", "", false
	}

	mapped, ok := completionOutcomes[e.block.State]

	return mapped[0], mapped[1], ok
}

// sessionReused reports an OIDC flow that /authorize started for an already authenticated session.
func (e completionEvidence) sessionReused() bool {
	return e.issuance != nil && e.issuance.Reason == reasonExistingSession
}

// stepState states whether a completion step of an authorization-code flow was recorded.
func (e completionEvidence) stepState(eventType string, completion []AuthEventRecord) string {
	if e.block == nil {
		return stepNotApplicable
	}

	if slices.ContainsFunc(completion, func(record AuthEventRecord) bool { return record.EventType == eventType }) {
		return stepRecorded
	}

	return stepNotRecorded
}

// completionGap names the completion gap of a flow without final outcome: not observed in the recorded era, an OIDC
// flow without any recorded grant in the recorded era, or the unchanged "never recorded" otherwise (SAML, device code,
// and every flow before completion recording).
func (e completionEvidence) completionGap() string {
	switch {
	case e.block != nil && e.block.State != completionNotRecorded:
		return gapCompletionNotObserved
	case e.block == nil && e.oidc && !e.grantKnown && e.recorded:
		return gapCompletionUndecidable
	default:
		return gapNoFlowCompletion
	}
}
