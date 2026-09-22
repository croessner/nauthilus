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
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/errors"
)

// newBackendBookkeepingAuth returns an AuthState with a silent logger, which is
// all checkAllBackends needs.
func newBackendBookkeepingAuth() *AuthState {
	return &AuthState{
		deps: AuthDeps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
	}
}

// TestConfigErrorsAreKeptPerBackendInstance pins that two pools of one backend
// type are counted separately.
//
// checkAllBackends fails the request only when every real backend had a
// configuration error. While the bookkeeping was keyed by backend type alone,
// one pool's entry was found again when the other pool was looked up, so a
// chain of two LDAP pools reported "all backends failed" as soon as a single
// pool declined or was misconfigured. That answers a temporary failure for an
// unknown user while a known user with a wrong password still gets a rejection
// from the healthy pool - a difference that can be measured from outside and
// used to enumerate accounts.
func TestConfigErrorsAreKeptPerBackendInstance(t *testing.T) {
	healthy := &PassDBMap{backend: definitions.BackendLDAP, name: "default"}
	declining := &PassDBMap{backend: definitions.BackendLDAP, name: "secondary"}
	passDBs := []*PassDBMap{
		{backend: definitions.BackendCache, name: definitions.DefaultBackendName},
		healthy,
		declining,
	}

	configErrors := map[backendInstance]error{
		declining.instance(): errors.ErrBackendNotResponsible,
	}

	if err := checkAllBackends(configErrors, passDBs, newBackendBookkeepingAuth()); err != nil {
		t.Fatalf("one pool declining must not fail a chain the other pool serves, got %v", err)
	}

	// Once every real backend is accounted for, the request is genuinely
	// unserviceable and must answer a temporary failure.
	configErrors[healthy.instance()] = errors.ErrLDAPConfig

	err := checkAllBackends(configErrors, passDBs, newBackendBookkeepingAuth())
	if !stderrors.Is(err, errors.ErrAllBackendConfigError) {
		t.Fatalf("a chain where every real backend failed must answer a temporary failure, got %v", err)
	}
}

// TestConfigErrorDetailsNameTheFailingPool pins that the operator-facing detail
// distinguishes the pools, which is the whole point of keying by instance.
func TestConfigErrorDetailsNameTheFailingPool(t *testing.T) {
	details := collectConfigErrorDetails(map[backendInstance]error{
		{backend: definitions.BackendLDAP, name: "secondary"}:                   errors.ErrLDAPConfig.WithDetail("no such protocol"),
		{backend: definitions.BackendLua, name: definitions.DefaultBackendName}: errors.ErrLuaConfig.WithDetail("missing section"),
	})

	if !strings.Contains(details, "secondary") {
		t.Fatalf("the failing pool must be named, got %q", details)
	}

	// The default instance carries no name worth printing.
	if strings.Contains(details, definitions.DefaultBackendName) {
		t.Fatalf("the internal default name must not leak into operator output, got %q", details)
	}
}

// TestBackendPositionsIgnoreSkippedAndLaterPools pins which position a backend
// type occupies in the chain, because that decides whether a positive password
// cache entry may be written.
//
// Two mistakes were possible. A configured entry the chain skipped, such as a
// lookup-only LDAP pool, still recorded its position, and the last write won -
// so a skipped pool sitting after the cache made the cache look like it fronted
// a pool that in truth ran before it. The same held for two pools that straddle
// the cache. Either way a positive entry was written for results the cache does
// not front, which can serve a stale success after the account is gone.
func TestBackendPositionsIgnoreSkippedAndLaterPools(t *testing.T) {
	for _, tc := range []struct {
		name string
		// record replays one chain as buildBackendExecutionPlan would.
		record func(plan *backendExecutionPlan)
		// want is the position the type must end up with, -1 for none.
		want int
	}{
		{
			name: "a skipped pool does not claim a position",
			record: func(plan *backendExecutionPlan) {
				plan.recordPosition(definitions.BackendLDAP, 0, true)
				plan.recordPosition(definitions.BackendCache, 1, true)
				// A lookup-only pool is configured but never appended.
				plan.recordPosition(definitions.BackendLDAP, 2, false)
			},
			want: 0,
		},
		{
			name: "the earliest pool of a type wins",
			record: func(plan *backendExecutionPlan) {
				plan.recordPosition(definitions.BackendLDAP, 0, true)
				plan.recordPosition(definitions.BackendCache, 1, true)
				plan.recordPosition(definitions.BackendLDAP, 2, true)
			},
			want: 0,
		},
		{
			name: "a type whose every entry was skipped has no position",
			record: func(plan *backendExecutionPlan) {
				plan.recordPosition(definitions.BackendLDAP, 0, false)
			},
			want: -1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := backendExecutionPlan{positions: make(map[definitions.Backend]int)}
			tc.record(&plan)

			got, ok := plan.positions[definitions.BackendLDAP]
			if tc.want < 0 {
				if ok {
					t.Fatalf("expected no position, got %d", got)
				}

				return
			}

			if !ok {
				t.Fatal("expected a recorded position, got none")
			}

			if got != tc.want {
				t.Fatalf("expected position %d, got %d", tc.want, got)
			}

			// The cache sits at index 1 in both straddle cases, so it must not
			// be treated as fronting a pool that runs before it.
			plan.hasPositivePasswordCache = true
			if plan.positivePasswordCacheEnabled(definitions.BackendLDAP) {
				t.Fatal("the cache does not front the pool that runs first; caching its result can serve a stale success")
			}
		})
	}
}
