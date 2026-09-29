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
	stderrors "errors"
	"log/slog"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/stats"
)

// authnAdmissionRejections turns transient Policy admission capacity rejections into temporary failures.
//
// Only capacity exhaustion (profile concurrency or rate) reported before a session was admitted is
// retryable. Every other admission, authentication, or configuration failure stays fail-closed.
type authnAdmissionRejections struct {
	logger *slog.Logger
}

// tempFail returns a complete temporary-failure result when err is a pre-admission capacity rejection.
func (r authnAdmissionRejections) tempFail(
	input AuthInput,
	operation policy.Operation,
	err error,
) (authnApplicationResult, bool) {
	reason, ok := authnAdmissionCapacityReason(err)
	if !ok {
		return authnApplicationResult{}, false
	}

	result := newAuthnAdmissionTempFailResult(input, operation)
	r.observe(input, operation, reason, result.session())

	return result, true
}

// observe records one rejected session with a bounded warning and the low-cardinality reason counter.
func (r authnAdmissionRejections) observe(input AuthInput, operation policy.Operation, reason string, session string) {
	stats.GetMetrics().GetPolicyAuthnAdmissionRejectionsTotal().WithLabelValues(reason).Inc()

	logger := r.logger
	if logger == nil {
		logger = slog.Default()
	}

	level.Warn(logger).Log(
		definitions.LogKeyGUID, session,
		definitions.LogKeyMsg, "Internal authentication rejected by Policy admission capacity",
		"reason", reason,
		"operation", string(operation),
		"entry_point", input.EntryPoint.String(),
		definitions.LogKeyProtocol, input.Context.Protocol,
	)
}

// authnAdmissionCapacityReason classifies only Decision Service admission rejections caused by capacity.
func authnAdmissionCapacityReason(err error) (string, bool) {
	if !stderrors.Is(err, decisionservice.ErrDecisionAdmission) {
		return "", false
	}

	return admission.CapacityRejectionReason(err)
}

// newAuthnAdmissionTempFailResult builds the operation-specific temporary failure without host execution.
func newAuthnAdmissionTempFailResult(input AuthInput, operation policy.Operation) authnApplicationResult {
	if operation == policy.OperationListAccounts {
		return authnApplicationResult{accounts: newListAccountsTempFailOutcome(input)}
	}

	return authnApplicationResult{auth: newAuthTempFailOutcome(input)}
}

// session returns the correlation session of whichever operation outcome the result carries.
func (r authnApplicationResult) session() string {
	if r.auth != nil {
		return r.auth.Session
	}

	if r.accounts != nil {
		return r.accounts.Session
	}

	return ""
}
