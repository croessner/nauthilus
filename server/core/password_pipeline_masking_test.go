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
	"errors"
	"testing"

	nautherrors "github.com/croessner/nauthilus/v4/server/errors"
)

// pipelineMaskingCase describes one pipeline state and the answer it must give.
type pipelineMaskingCase struct {
	name string
	// setup prepares the state after the cache and the next backend have run.
	setup func(state *passwordPipelineState)
	// wantErr is the error the pipeline must surface instead of a result.
	wantErr error
	// wantResult is set when the pipeline may keep its result.
	wantResult bool
}

// pipelineMaskingCases covers the combinations of a stored result and a
// recorded backend failure.
func pipelineMaskingCases() []pipelineMaskingCase {
	cacheMiss := func() *PassDBResult {
		return &PassDBResult{Authenticated: false, UserFound: false}
	}

	unclassified := errors.New("ldap: connection closed")

	return []pipelineMaskingCase{
		{
			name: "classified failure after a cache miss surfaces the error",
			setup: func(state *passwordPipelineState) {
				state.finalRes = cacheMiss()
				state.tempfailErr = nautherrors.ErrBackendTemporaryFailure
			},
			wantErr: nautherrors.ErrBackendTemporaryFailure,
		},
		{
			name: "unclassified failure after a cache miss surfaces the error",
			setup: func(state *passwordPipelineState) {
				state.finalRes = cacheMiss()
				state.unclassifiedErr = unclassified
			},
			wantErr: unclassified,
		},
		{
			name: "a classified failure is preferred when both were recorded",
			setup: func(state *passwordPipelineState) {
				state.finalRes = cacheMiss()
				state.unclassifiedErr = unclassified
				state.tempfailErr = nautherrors.ErrLDAPBindTimeout
			},
			wantErr: nautherrors.ErrLDAPBindTimeout,
		},
		{
			name: "a successful authentication survives an earlier failure",
			setup: func(state *passwordPipelineState) {
				state.finalRes = &PassDBResult{Authenticated: true, UserFound: true}
				state.unclassifiedErr = unclassified
			},
			wantResult: true,
		},
		{
			name: "an authoritative rejection still rejects",
			setup: func(state *passwordPipelineState) {
				// UserFound means a backend looked the account up and turned
				// the password down. That is a real verdict and must keep
				// counting, or brute force would go unrecorded.
				state.finalRes = &PassDBResult{Authenticated: false, UserFound: true}
				state.unclassifiedErr = unclassified
			},
			wantResult: true,
		},
		{
			name: "a clean miss with no failure stays a miss",
			setup: func(state *passwordPipelineState) {
				state.finalRes = cacheMiss()
			},
			wantResult: true,
		},
	}
}

// decliningBackendCases cover backends that were never meant to serve the
// request, as opposed to backends that tried and could not.
func decliningBackendCases() []pipelineMaskingCase {
	cacheMiss := func() *PassDBResult {
		return &PassDBResult{Authenticated: false, UserFound: false}
	}

	return []pipelineMaskingCase{
		{
			// A split chain, say LDAP for imap and Lua for smtp, has one
			// backend decline every request it does not serve. If that counted
			// as a failure, every unknown user on the split protocol would get
			// a temporary failure while a known user with a wrong password got
			// a rejection - which tells an attacker the two apart.
			name: "a backend that declines does not suppress a later rejection",
			setup: func(state *passwordPipelineState) {
				state.recordBackendError(nautherrors.ErrBackendNotResponsible)
				state.finalRes = cacheMiss()
			},
			wantResult: true,
		},
		{
			// An LDAP config error is not a decline. Most of them mean a
			// broken or half-configured pool, and some are raised after the
			// user was already found, for instance when a stored TOTP secret
			// cannot be decrypted. Reading those as declines would let a
			// broken backend hand the verdict to one that never saw the user.
			name: "a config error is not a decline and still suppresses",
			setup: func(state *passwordPipelineState) {
				state.recordBackendError(nautherrors.ErrLDAPConfig)
				state.finalRes = cacheMiss()
			},
			wantErr: nautherrors.ErrLDAPConfig,
		},
		{
			name: "a lua config error is not a decline either",
			setup: func(state *passwordPipelineState) {
				state.recordBackendError(nautherrors.ErrLuaConfig)
				state.finalRes = cacheMiss()
			},
			wantErr: nautherrors.ErrLuaConfig,
		},
		{
			// Declining is not failing, so a chain where every backend declines
			// is decided by checkAllBackends, not here.
			name: "a real failure still wins over a declining backend",
			setup: func(state *passwordPipelineState) {
				state.recordBackendError(nautherrors.ErrBackendNotResponsible)
				state.recordBackendError(nautherrors.ErrBackendTemporaryFailure)
				state.finalRes = cacheMiss()
			},
			wantErr: nautherrors.ErrBackendTemporaryFailure,
		},
	}
}

// TestBackendFailureIsNotMaskedByAnEarlierNegativeResult pins the invariant that
// keeps a backend outage from being answered as a wrong password.
//
// With the usual backend order the cache runs first. A cache miss leaves a
// result that neither authenticates nor finds the user, and the authoritative
// backend runs next. If that backend then fails, the pipeline holds both a
// negative result and an error. Returning the negative result would tell the
// caller "these credentials are wrong" on the strength of a cache miss, and the
// caller counts that against the client's address. The error has to win, and it
// has to win for errors no layer classified too - those are exactly the ones
// nobody anticipated.
func TestBackendFailureIsNotMaskedByAnEarlierNegativeResult(t *testing.T) {
	cases := append(pipelineMaskingCases(), decliningBackendCases()...)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := newPasswordPipelineState()
			tc.setup(&state)

			result, err := state.finalPasswordResult()

			if tc.wantResult {
				if err != nil {
					t.Fatalf("expected the result to be kept, got error %v", err)
				}

				if result == nil {
					t.Fatal("expected a result, got nil")
				}

				return
			}

			if result != nil {
				t.Fatalf("a backend failure was masked by a negative result: %+v", result)
			}

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestUnclassifiedBackendErrorIsRecorded pins that an error no layer recognised
// is still remembered, so it can override a negative result. Classified errors
// keep their own field so the logs name the precise cause.
func TestUnclassifiedBackendErrorIsRecorded(t *testing.T) {
	state := newPasswordPipelineState()

	unclassified := errors.New("unable to read LDAP response packet: EOF")
	state.recordBackendError(unclassified)

	if state.tempfailErr != nil {
		t.Fatalf("an unrecognised error must not be reported as classified, got %v", state.tempfailErr)
	}

	if !errors.Is(state.undecidedErr(), unclassified) {
		t.Fatalf("expected the unclassified error to decide, got %v", state.undecidedErr())
	}

	state.recordBackendError(nautherrors.ErrLDAPPoolExhausted)

	if !errors.Is(state.undecidedErr(), nautherrors.ErrLDAPPoolExhausted) {
		t.Fatalf("a classified error must take precedence, got %v", state.undecidedErr())
	}

	// The first unclassified error stays recorded so nothing is lost.
	if !errors.Is(state.unclassifiedErr, unclassified) {
		t.Fatalf("expected the first unclassified error to be kept, got %v", state.unclassifiedErr)
	}
}
