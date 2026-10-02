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
// observed.
type authnHostEvidence struct {
	credential definitions.AuthResult
	accounts   definitions.AuthResult
}

// freezeCredential records the first backend verification verdict and ignores every later attempt to replace it.
func (h *authnHostEvidence) freezeCredential(result definitions.AuthResult) {
	if h.credential == definitions.AuthResultUnset {
		h.credential = result
	}
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

// hostEvent names the auth FSM event the frozen verdict of operation maps to, for diagnostics only.
func (h authnHostEvidence) hostEvent(operation policy.Operation) string {
	event, ok := mapAuthPasswordResultToFSMEvent(h.verdict(operation))
	if !ok {
		return authnHostEventNone
	}

	return string(event)
}

// settleCredential records one host-owned backend verdict as the current result and freezes it as auth FSM evidence.
func (e *authnCandidateExecution) settleCredential(result definitions.AuthResult) {
	e.authResult = result
	e.hostEvidence.freezeCredential(result)
}

// enforceHostCredentialBound keeps subject providers from raising a credential the host did not verify. A subject
// may reject a verified credential, but a raised result, backend flag, or request flag is reset to the frozen
// verdict, so later subjects, the positive password cache, post-actions, and Policy facts never observe it.
func (e *authnCandidateExecution) enforceHostCredentialBound() {
	if e.hostEvidence.permits(e.operation) {
		return
	}

	raised := e.authResult == definitions.AuthResultOK || e.auth.Runtime.Authenticated ||
		e.backendResult != nil && e.backendResult.Authenticated
	if !raised {
		return
	}

	e.authResult = e.hostEvidence.credential
	if e.authResult == definitions.AuthResultUnset {
		e.authResult = definitions.AuthResultFail
	}

	if e.backendResult != nil {
		e.backendResult.Authenticated = false
	}

	e.auth.Runtime.Authenticated = false

	level.Warn(e.auth.Logger()).Log(
		definitions.LogKeyGUID, e.auth.Runtime.GUID,
		definitions.LogKeyMsg, "Subject provider tried to raise an unverified credential; the host verdict is kept",
		"operation", string(e.operation),
		"host_event", e.hostEvidence.hostEvent(e.operation),
	)
}

// AuthnPermitBacked reports whether the frozen host evidence backs a permit of this request's operation. The Decision
// Service consults it before dispatching effects, so an unbacked permit runs no obligation, post-action, or advice;
// finalize then answers it as a temporary failure and records the violation once.
func (e *authnCandidateExecution) AuthnPermitBacked(_ context.Context, target decision.Target, _ string) bool {
	return e != nil && target.Action() == string(e.operation) && e.hostEvidence.permits(e.operation)
}

// guardAuthnPermit enforces the host-evidence auth FSM on a selected permit. Deny and tempfail only tighten and pass
// unchanged; a permit the frozen host verdict does not back is replaced by a fail-closed temporary failure.
func (e *authnCandidateExecution) guardAuthnPermit(
	checkpoint string,
	effect decision.Effect,
	presentation *report.FinalDecision,
) (decision.Effect, *report.FinalDecision) {
	if effect != decision.EffectPermit || e.hostEvidence.permits(e.operation) {
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
		"host_event", e.hostEvidence.hostEvent(e.operation),
	)
}

// authnHostFSMEventPath returns the auth FSM path of the enforced terminal decision. The host owns the parser,
// pre-auth, and evaluation steps and the success event; a selected rule contributes only its tightening event.
func (e *authnCandidateExecution) authnHostFSMEventPath(presentation *report.FinalDecision) []string {
	if presentation == nil {
		return []string{policy.FSMEventMarkerParseOK}
	}

	return append(policyfsm.CheckpointEventPrefix(e.operation, presentation.Stage), authnTerminalFSMEvent(presentation))
}

// authnTerminalFSMEvent returns the terminal event of an enforced decision. A permit only reaches this point after
// the host guard accepted it; deny and tempfail use the rule marker or the marker derived for their decision.
func authnTerminalFSMEvent(presentation *report.FinalDecision) string {
	if presentation.Effect == policy.DecisionPermit {
		return policy.FSMEventMarkerAuthPermit
	}

	if presentation.FSMEventMarker != "" {
		return presentation.FSMEventMarker
	}

	return policyfsm.DefaultRuleMarker(presentation.Stage, presentation.Effect)
}
