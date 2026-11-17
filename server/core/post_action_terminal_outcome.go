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
	"sync"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/report"
)

// authnTerminalOutcomeCell holds the terminal outcome of exactly one authn application run. Native post-actions
// capture their request before finalize applies the answer, so they resolve this cell when they execute after the
// finalization gate. One client request can run several authn sessions, therefore the cell belongs to the run and not
// to the request context.
type authnTerminalOutcomeCell struct {
	outcome pluginapi.AuthOutcome
	mu      sync.Mutex
	sealed  bool
}

// seal stores the terminal outcome once; later seals of the same run are ignored.
func (c *authnTerminalOutcomeCell) seal(outcome pluginapi.AuthOutcome) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sealed {
		return
	}

	outcome.Known = true
	c.outcome = outcome
	c.sealed = true
}

// load returns the sealed outcome, or an unknown outcome when the run never sealed one.
func (c *authnTerminalOutcomeCell) load() pluginapi.AuthOutcome {
	if c == nil {
		return pluginapi.AuthOutcome{Decision: pluginapi.AuthOutcomeUnknown}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.sealed {
		return pluginapi.AuthOutcome{Decision: pluginapi.AuthOutcomeUnknown}
	}

	return c.outcome
}

// PostActionTransportRecorder records how one client request was answered. It is request-scoped because all authn
// runs of one request share the same response.
type PostActionTransportRecorder struct {
	transport pluginapi.AuthTransport
	mu        sync.Mutex
	status    int
}

type postActionTransportRecorderContextKey struct{}

// newPostActionTransportRecorder maps the finalization boundary to its public transport name.
func newPostActionTransportRecorder(boundary effectsupervisor.Boundary) *PostActionTransportRecorder {
	recorder := &PostActionTransportRecorder{}

	switch boundary {
	case effectsupervisor.BoundaryHTTPCommit:
		recorder.transport = pluginapi.AuthTransportHTTP
	case effectsupervisor.BoundaryGRPCUnaryReturn:
		recorder.transport = pluginapi.AuthTransportGRPC
	}

	return recorder
}

// RecordStatus stores the committed HTTP status. Non-HTTP transports ignore it.
func (r *PostActionTransportRecorder) RecordStatus(status int) {
	if r == nil || r.transport != pluginapi.AuthTransportHTTP || status <= 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.status = status
}

// apply copies the transport facts into a resolved outcome.
func (r *PostActionTransportRecorder) apply(outcome *pluginapi.AuthOutcome) {
	if r == nil || outcome == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	outcome.Transport = r.transport
	outcome.TransportStatus = r.status
}

// contextWithPostActionTransportRecorder installs a recorder for the gate's boundary unless one exists.
func contextWithPostActionTransportRecorder(
	ctx context.Context,
	gate *PostActionExecutionGate,
) context.Context {
	if ctx == nil || gate == nil || PostActionTransportRecorderFromContext(ctx) != nil {
		return ctx
	}

	return context.WithValue(ctx, postActionTransportRecorderContextKey{}, newPostActionTransportRecorder(gate.Boundary()))
}

// PostActionTransportRecorderFromContext returns the request-scoped transport recorder when installed.
func PostActionTransportRecorderFromContext(ctx context.Context) *PostActionTransportRecorder {
	if ctx == nil {
		return nil
	}

	recorder, _ := ctx.Value(postActionTransportRecorderContextKey{}).(*PostActionTransportRecorder)

	return recorder
}

// postActionOutcomeBinding resolves the terminal outcome for one detached post-action when it executes.
type postActionOutcomeBinding struct {
	cell      *authnTerminalOutcomeCell
	transport *PostActionTransportRecorder
}

// bind attaches the resolved outcome and refreshes the snapshot diagnostics that describe the answer.
func (b postActionOutcomeBinding) bind(request *pluginapi.PostActionRequest) {
	if request == nil {
		return
	}

	outcome := b.cell.load()
	b.transport.apply(&outcome)

	request.Outcome = outcome
	request.Snapshot.Diagnostics.HTTPStatus = outcome.HTTPStatus
	request.Snapshot.Diagnostics.StatusMessage = outcome.StatusMessage
}

// sealTerminalOutcome records the answered result of this run for post-actions that execute after the gate and
// reports whether a known outcome was sealed.
func (e *authnCandidateExecution) sealTerminalOutcome(result authnApplicationResult) bool {
	if e == nil || e.auth == nil {
		return false
	}

	decision := pluginOutcomeDecision(result.currentDecision())
	if decision == pluginapi.AuthOutcomeUnknown {
		return false
	}

	outcome := pluginapi.AuthOutcome{
		Decision:  decision,
		Operation: string(e.operation),
		FSMState:  e.auth.Runtime.AuthFSMTerminalState,
	}

	outcome.HTTPStatus, outcome.StatusMessage = result.answeredStatus()
	applyPresentedDecision(&outcome, e.presentedDecision())

	if decision == pluginapi.AuthOutcomeTempFail {
		applyTempFailCause(&outcome, e.auth.Runtime.tempFailCause)
	}

	e.outcome.seal(outcome)

	return true
}

// outcomeBinding returns the binding that detached post-actions of this run resolve at execution time.
func (e *authnCandidateExecution) outcomeBinding() postActionOutcomeBinding {
	if e == nil {
		return postActionOutcomeBinding{}
	}

	return postActionOutcomeBinding{cell: e.outcome, transport: e.transport}
}

// recordPresentedDecision stores the presentation the latest finalized checkpoint answers with; nil clears it.
func (e *authnCandidateExecution) recordPresentedDecision(presentation *report.FinalDecision) {
	if e == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.presented = report.CloneFinalDecision(presentation)
}

// presentedDecision returns a detached copy of the latest finalized presentation.
func (e *authnCandidateExecution) presentedDecision() *report.FinalDecision {
	if e == nil {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	return report.CloneFinalDecision(e.presented)
}

// answeredStatus returns the host status code and client text of the application result.
func (r authnApplicationResult) answeredStatus() (int, string) {
	if r.auth != nil {
		return r.auth.HTTPStatus, r.auth.StatusMessage
	}

	if r.accounts != nil {
		return r.accounts.HTTPStatus, r.accounts.StatusMessage
	}

	return 0, ""
}

// pluginOutcomeDecision maps the host decision vocabulary onto the public terminal vocabulary.
func pluginOutcomeDecision(decision AuthDecision) pluginapi.AuthOutcomeDecision {
	switch decision {
	case AuthDecisionOK:
		return pluginapi.AuthOutcomeOK
	case AuthDecisionFail:
		return pluginapi.AuthOutcomeFail
	case AuthDecisionTempFail:
		return pluginapi.AuthOutcomeTempFail
	default:
		return pluginapi.AuthOutcomeUnknown
	}
}

// applyPresentedDecision copies the stable Policy markers of the presenting rule.
func applyPresentedDecision(outcome *pluginapi.AuthOutcome, presented *report.FinalDecision) {
	if outcome == nil || presented == nil {
		return
	}

	outcome.Stage = string(presented.Stage)
	outcome.OutcomeMarker = presented.OutcomeMarker
	outcome.ResponseMarker = presented.ResponseMarker
	outcome.PolicyRule = presented.PolicyName
}

// applyTempFailCause copies the bounded temporary-failure cause that the terminal tempfail log line reports.
func applyTempFailCause(outcome *pluginapi.AuthOutcome, cause authTempFailCause) {
	if outcome == nil {
		return
	}

	outcome.TempFailReason = cause.reason
	outcome.TempFailCheckpoint = cause.checkpoint
	outcome.PolicyStatus = cause.statusCode

	if outcome.PolicyRule == "" {
		outcome.PolicyRule = cause.policyRule
	}

	if outcome.OutcomeMarker == "" {
		outcome.OutcomeMarker = cause.outcome
	}
}
