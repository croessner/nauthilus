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

	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
)

// tolerationObservation is the toleration outcome of one authenticate run, captured inside the decision session and
// written after the session slot is released.
type tolerationObservation struct {
	toleration    tolerate.Tolerate
	clientIP      string
	username      string
	authenticated bool
}

// tolerationObservation captures the brute-force toleration outcome of one authenticate run. The counters drive IP
// toleration and the reputation-scaled bucket limits; the auth FSM dispatch that wrote them was retired with the
// Policy authority cutover without a replacement. Only host-verified credential outcomes count: an answered success
// backed by a verified credential is positive, an answered failure backed by a rejected credential is negative.
// A failure that repeats an already recorded wrong password (RWP) is not negative, mirroring the bucket counters, so a
// client retrying one stale password cannot exhaust the toleration of a shared address. Temporary failures, pre-auth
// rejections, lookups, and no-auth requests are not accounted.
func (e *authnCandidateExecution) tolerationObservation(result authnApplicationResult) (tolerationObservation, bool) {
	if e == nil || e.auth == nil || e.operation != policy.OperationAuthenticate || e.auth.Request.NoAuth {
		return tolerationObservation{}, false
	}

	toleration := e.auth.deps.Tolerate
	if toleration == nil {
		return tolerationObservation{}, false
	}

	authenticated, accounted := tolerationVerdict(result.currentDecision(), e.hostEvidenceSnapshot().credential, e.auth.Runtime.BFRWP)
	if !accounted {
		return tolerationObservation{}, false
	}

	return tolerationObservation{
		toleration:    toleration,
		clientIP:      e.auth.Request.ClientIP,
		username:      tolerationAccount(e.auth),
		authenticated: authenticated,
	}, true
}

// tolerationAccount names the account a toleration observation is keyed by. The resolved account keeps aliases of one
// mailbox from counting as several distinct successful accounts; the typed username is the fallback.
func tolerationAccount(auth *AuthState) string {
	if account := auth.GetAccount(); account != "" {
		return account
	}

	return auth.Request.Username
}

// record writes the captured outcome into the toleration counters. It runs outside the decision session so the Redis
// write never holds a session slot; it cannot change the answered decision.
func (o tolerationObservation) record(ctx context.Context) {
	o.toleration.SetIPAddress(ctx, o.clientIP, o.username, o.authenticated)
}

// tolerationVerdict maps the answered decision, the frozen host credential verdict and the request's RWP allowance onto
// one toleration observation.
func tolerationVerdict(
	decision AuthDecision,
	credential definitions.AuthResult,
	repeatedWrongPassword bool,
) (authenticated bool, accounted bool) {
	switch {
	case decision == AuthDecisionOK && credential == definitions.AuthResultOK:
		return true, true
	case decision == AuthDecisionFail && credential == definitions.AuthResultFail && !repeatedWrongPassword:
		return false, true
	default:
		return false, false
	}
}
