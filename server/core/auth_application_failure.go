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
	"log/slog"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/monitoring/authmetrics"
	"github.com/croessner/nauthilus/v4/server/stats"
)

// AuthApplicationFailures answers unexpected auth application errors with a fail-closed temporary failure.
//
// Transport adapters keep mapping typed application errors (input, permission, preprocess rejection) themselves
// and hand every remaining error to this type. The exact cause is logged at error level and counted by a bounded
// transport label; the caller receives the regular temporary-failure outcome and is never authenticated.
type AuthApplicationFailures struct {
	logger    *slog.Logger
	transport string
}

// NewAuthApplicationFailures binds failure handling to one logger and one authentication transport.
//
// transport is bounded to the authentication metric transport labels (http, grpc, other).
func NewAuthApplicationFailures(logger *slog.Logger, transport string) AuthApplicationFailures {
	return AuthApplicationFailures{logger: logger, transport: authmetrics.NormalizeTransport(transport)}
}

// TempFail records err and returns the temporary-failure outcome for an authenticate or lookup operation.
func (f AuthApplicationFailures) TempFail(input AuthInput, err error) *AuthOutcome {
	outcome := newAuthTempFailOutcome(input)
	f.observe(input, outcome.Session, err)

	return outcome
}

// ListAccountsTempFail records err and returns the temporary-failure outcome for an account listing.
func (f AuthApplicationFailures) ListAccountsTempFail(input AuthInput, err error) *ListAccountsOutcome {
	outcome := newListAccountsTempFailOutcome(input)
	f.observe(input, outcome.Session, err)

	return outcome
}

// observe logs the exact cause with request correlation and increments the bounded transport counter.
func (f AuthApplicationFailures) observe(input AuthInput, session string, err error) {
	stats.GetMetrics().GetAuthApplicationErrorsTotal().WithLabelValues(f.transport).Inc()

	logger := f.logger
	if logger == nil {
		logger = slog.Default()
	}

	level.Error(logger).Log(
		definitions.LogKeyGUID, session,
		definitions.LogKeyMsg, "Authentication application failed",
		definitions.LogKeyError, err,
		"transport", f.transport,
		"mode", string(input.Mode),
		definitions.LogKeyProtocol, input.Context.Protocol,
	)
}

// newAuthTempFailOutcome builds the regular authenticate or lookup temporary failure for one request.
func newAuthTempFailOutcome(input AuthInput) *AuthOutcome {
	outcome := &AuthOutcome{
		Decision: AuthDecisionTempFail,
		Session:  authApplicationCorrelationID(input.CorrelationID),
		Protocol: input.Context.Protocol,
	}
	applyAuthnCandidateTempFail(outcome)

	return outcome
}

// newListAccountsTempFailOutcome builds the regular empty account-listing temporary failure for one request.
func newListAccountsTempFailOutcome(input AuthInput) *ListAccountsOutcome {
	outcome := &ListAccountsOutcome{
		Decision: AuthDecisionTempFail,
		Session:  authApplicationCorrelationID(input.CorrelationID),
		Protocol: input.Context.Protocol,
	}
	applyAuthnCandidateListTempFail(outcome)

	return outcome
}
