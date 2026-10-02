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

package core

import (
	"context"
	"slices"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyfsm "github.com/croessner/nauthilus/v4/server/policy/fsm"
	"github.com/croessner/nauthilus/v4/server/policy/report"
	"github.com/croessner/nauthilus/v4/server/stats"
)

const (
	authnFSMGuardOutcomeMarker  = "auth.outcome.fsm_guard_violation"
	authnFSMGuardResponseSource = "fsm_guard"
	authnHostEventNone          = "none"
)

// authnHostEvidence holds the host-owned verdicts that drive the auth FSM for one request.
//
// The host freezes a verdict when backend verification or the account provider completes, before any subject
// provider, plugin patch, cached projection, or Policy fact can observe it. A frozen verdict is never replaced or
// raised; only a later host-owned failure may lower a success. AuthResultUnset marks a verdict the host never
// observed. identityFound records whether the backend found the identity when it froze the credential.
type authnHostEvidence struct {
	credential    definitions.AuthResult
	accounts      definitions.AuthResult
	identityFound bool
}

// freezeCredential records the first backend verification verdict, ignores every later attempt to replace it, and
// returns the frozen verdict.
func (h *authnHostEvidence) freezeCredential(result definitions.AuthResult, identityFound bool) definitions.AuthResult {
	if h.credential == definitions.AuthResultUnset {
		h.credential = result
		h.identityFound = identityFound
	}

	return h.credential
}

// freezeAccounts records the first account provider verdict and ignores every later attempt to replace it.
func (h *authnHostEvidence) freezeAccounts(result definitions.AuthResult) {
	if h.accounts == definitions.AuthResultUnset {
		h.accounts = result
	}
}

// lowerCredential replaces a verified credential with a later host-owned failure; it never raises a verdict.
func (h *authnHostEvidence) lowerCredential(result definitions.AuthResult) {
	if h.credential == definitions.AuthResultOK && result != definitions.AuthResultOK {
		h.credential = result
	}
}

// verdict returns the frozen verdict that backs a permit of operation.
func (h authnHostEvidence) verdict(operation policy.Operation) definitions.AuthResult {
	if operation == policy.OperationListAccounts {
		return h.accounts
	}

	return h.credential
}

// permits reports whether the frozen host verdict proves the success a permit of operation would announce.
func (h authnHostEvidence) permits(operation policy.Operation) bool {
	return h.verdict(operation) == definitions.AuthResultOK
}

// hostEvent names the auth FSM event the frozen verdict of operation maps to, or authnHostEventNone.
func (h authnHostEvidence) hostEvent(operation policy.Operation) string {
	return authnVerdictEvent(h.verdict(operation))
}

// authnVerdictEvent names the auth FSM event of one host verdict, or authnHostEventNone when it has none.
func authnVerdictEvent(result definitions.AuthResult) string {
	event, ok := mapAuthPasswordResultToFSMEvent(result)
	if !ok {
		return authnHostEventNone
	}

	return string(event)
}

// hostEvidenceSnapshot returns the host evidence under the execution lock, so Decision Service callbacks never read
// it while the host writes it.
func (e *authnCandidateExecution) hostEvidenceSnapshot() authnHostEvidence {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.hostEvidence
}

// updateHostEvidence applies one host-owned change to the evidence under the execution lock.
func (e *authnCandidateExecution) updateHostEvidence(update func(*authnHostEvidence)) {
	e.mu.Lock()
	defer e.mu.Unlock()

	update(&e.hostEvidence)
}

// settleCredential freezes one host-owned backend verdict as auth FSM evidence and makes the frozen verdict the
// current result. The first verdict wins: a second, different verdict is logged and never becomes the result.
func (e *authnCandidateExecution) settleCredential(result definitions.AuthResult, identityFound bool) {
	var frozen definitions.AuthResult

	e.updateHostEvidence(func(evidence *authnHostEvidence) {
		frozen = evidence.freezeCredential(result, identityFound)
	})

	if frozen != result {
		level.Warn(e.auth.Logger()).Log(
			definitions.LogKeyGUID, e.auth.Runtime.GUID,
			definitions.LogKeyMsg, "Second backend verdict ignored; the first frozen backend verdict is kept",
			"operation", string(e.operation),
			"host_event", authnVerdictEvent(frozen),
			"ignored_event", authnVerdictEvent(result),
		)
	}

	e.authResult = frozen
}

// enforceHostCredentialBound keeps subject providers from raising what the host did not verify. A subject may reject
// a verified credential or a found identity, but a raised result, authenticated flag, or user-found flag on the
// backend result or the request is reset to the frozen evidence, so later subjects, the positive password cache,
// post-actions, and Policy facts never observe it.
func (e *authnCandidateExecution) enforceHostCredentialBound() {
	evidence := e.hostEvidenceSnapshot()
	raisedCredential := e.clampSubjectCredential(evidence)
	raisedIdentity := e.clampSubjectIdentity(evidence)

	if !raisedCredential && !raisedIdentity {
		return
	}

	level.Warn(e.auth.Logger()).Log(
		definitions.LogKeyGUID, e.auth.Runtime.GUID,
		definitions.LogKeyMsg, "Subject provider tried to raise an unverified credential or identity; the host verdict is kept",
		"operation", string(e.operation),
		"host_event", evidence.hostEvent(e.operation),
		"raised_authenticated", raisedCredential,
		"raised_user_found", raisedIdentity,
	)
}

// clampSubjectCredential resets a subject-raised result and authenticated flags and reports whether it had to.
func (e *authnCandidateExecution) clampSubjectCredential(evidence authnHostEvidence) bool {
	if evidence.permits(e.operation) {
		return false
	}

	raised := e.authResult == definitions.AuthResultOK || e.auth.Runtime.Authenticated ||
		e.backendResult != nil && e.backendResult.Authenticated
	if !raised {
		return false
	}

	e.authResult = evidence.credential
	if e.authResult == definitions.AuthResultUnset {
		e.authResult = definitions.AuthResultFail
	}

	if e.backendResult != nil {
		e.backendResult.Authenticated = false
	}

	e.auth.Runtime.Authenticated = false

	return true
}

// clampSubjectIdentity resets subject-raised user-found flags and reports whether it had to.
func (e *authnCandidateExecution) clampSubjectIdentity(evidence authnHostEvidence) bool {
	if evidence.identityFound {
		return false
	}

	raised := e.auth.Runtime.UserFound || e.backendResult != nil && e.backendResult.UserFound
	if !raised {
		return false
	}

	if e.backendResult != nil {
		e.backendResult.UserFound = false
	}

	e.auth.Runtime.UserFound = false

	return true
}

// AuthnPermitBacked reports whether the frozen host evidence backs a permit of this request's operation. The Decision
// Service consults it before dispatching effects, so an unbacked permit runs no obligation, post-action, or advice;
// finalize then answers it as a temporary failure and records the violation once.
func (e *authnCandidateExecution) AuthnPermitBacked(_ context.Context, target decision.Target, _ string) bool {
	return e != nil && target.Action() == string(e.operation) && e.hostEvidenceSnapshot().permits(e.operation)
}

// guardAuthnPermit enforces the host-evidence auth FSM on a selected permit. Deny and tempfail only tighten and pass
// unchanged; a permit the frozen host verdict does not back is replaced by a fail-closed temporary failure.
func (e *authnCandidateExecution) guardAuthnPermit(
	checkpoint string,
	effect decision.Effect,
	presentation *report.FinalDecision,
) (decision.Effect, *report.FinalDecision) {
	if effect != decision.EffectPermit || e.hostEvidenceSnapshot().permits(e.operation) {
		return effect, presentation
	}

	e.recordAuthnFSMGuardViolation(checkpoint, presentation.PolicyName)

	return decision.EffectIndeterminate, authnCandidateTempFailDecision(
		presentation,
		authnFSMGuardOutcomeMarker,
		authnFSMGuardResponseSource,
	)
}

// recordAuthnFSMGuardViolation counts and logs one permit the host evidence contradicts, without credentials.
func (e *authnCandidateExecution) recordAuthnFSMGuardViolation(checkpoint string, policyRule string) {
	stats.GetMetrics().GetAuthnFSMGuardViolationsTotal().WithLabelValues(string(e.operation), checkpoint).Inc()

	level.Error(e.auth.Logger()).Log(
		definitions.LogKeyGUID, e.auth.Runtime.GUID,
		definitions.LogKeyMsg, "Policy permit rejected by the auth FSM guard: host evidence does not support success",
		"operation", string(e.operation),
		"checkpoint", checkpoint,
		"policy_rule", policyRule,
		"host_event", e.hostEvidenceSnapshot().hostEvent(e.operation),
	)
}

// authnHostFSMEventPath returns the auth FSM path of the enforced terminal decision. The host owns the parser,
// pre-auth, and evaluation steps and, whenever it is consistent with the decision, the terminal event.
func (e *authnCandidateExecution) authnHostFSMEventPath(presentation *report.FinalDecision) []string {
	if presentation == nil {
		return []string{policy.FSMEventMarkerParseOK}
	}

	prefix := policyfsm.CheckpointEventPrefix(e.operation, presentation.Stage)

	return append(prefix, e.authnTerminalFSMEvent(prefix, presentation))
}

// authnTerminalFSMEvent returns the terminal event of an enforced decision. The host event wins whenever it reaches
// the terminal state of that decision, so empty credentials and checked credentials keep their own event; otherwise a
// tightening decision uses the rule marker or the marker derived for it, and a guarded permit records auth_permit.
func (e *authnCandidateExecution) authnTerminalFSMEvent(prefix []string, presentation *report.FinalDecision) string {
	hostEvent := e.hostEvidenceSnapshot().hostEvent(e.operation)
	if hostEvent != authnHostEventNone &&
		authnFSMEventReaches(prefix, hostEvent, policyfsm.TerminalStateForDecision(presentation.Effect)) {
		return hostEvent
	}

	if presentation.Effect == policy.DecisionPermit {
		return policy.FSMEventMarkerAuthPermit
	}

	if presentation.FSMEventMarker != "" {
		return presentation.FSMEventMarker
	}

	return policyfsm.DefaultRuleMarker(presentation.Stage, presentation.Effect)
}

// authnFSMEventReaches reports whether event, applied after prefix, ends the auth FSM in terminal.
func authnFSMEventReaches(prefix []string, event string, terminal string) bool {
	if terminal == "" {
		return false
	}

	result, err := policyfsm.Evaluate(append(slices.Clone(prefix), event))

	return err == nil && result.TerminalState == terminal
}

// recordUnselectedAuthnFSM drives the host auth FSM for a finalization without a captured selection and projects
// the recorded path and terminal state onto the outcome, so telemetry and response agree on every path.
func (e *authnCandidateExecution) recordUnselectedAuthnFSM(
	checkpoint string,
	result authnApplicationResult,
) (authnApplicationResult, error) {
	selected, ok := authnPolicyDecisionFromAuthDecision(result.currentDecision())
	if !ok {
		return result, nil
	}

	presentation := &report.FinalDecision{Stage: policy.Stage(checkpoint), Effect: selected}
	if err := e.auth.applyAuthFSMMarkers(e.authnHostFSMEventPath(presentation)); err != nil {
		return authnApplicationResult{}, err
	}

	return result.withAuthnFSMTelemetry(e.auth.Runtime.AuthFSMEventPath, e.auth.Runtime.AuthFSMTerminalState), nil
}

// authnPolicyDecisionFromAuthDecision maps one public outcome category to the decision the auth FSM enforces.
func authnPolicyDecisionFromAuthDecision(outcome AuthDecision) (policy.Decision, bool) {
	switch outcome {
	case AuthDecisionOK:
		return policy.DecisionPermit, true
	case AuthDecisionFail:
		return policy.DecisionDeny, true
	case AuthDecisionTempFail:
		return policy.DecisionTempFail, true
	default:
		return "", false
	}
}

// withAuthnFSMTelemetry returns detached outcomes carrying the recorded auth FSM path and terminal state.
func (r authnApplicationResult) withAuthnFSMTelemetry(path []string, terminal string) authnApplicationResult {
	if r.auth != nil {
		r.auth = cloneAuthnCandidateOutcome(r.auth)

		r.auth.FSMEventPath = append([]string(nil), path...)
		r.auth.TerminalState = terminal
	}

	if r.accounts != nil {
		r.accounts = cloneAuthnCandidateListOutcome(r.accounts)

		r.accounts.FSMEventPath = append([]string(nil), path...)
		r.accounts.TerminalState = terminal
	}

	return r
}
