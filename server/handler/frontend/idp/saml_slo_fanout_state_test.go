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

package idp

import (
	"testing"
	"time"

	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/stretchr/testify/assert"
)

func TestNewSLOFanoutTransactionState(t *testing.T) {
	now := time.Date(2026, time.March, 19, 12, 0, 0, 0, time.UTC)

	baseParticipant := func(entityID, requestID string) slodomain.SLOParticipant {
		return slodomain.SLOParticipant{
			EntityID:  entityID,
			RequestID: requestID,
			Binding:   slodomain.SLOBindingRedirect,
		}
	}

	testCases := []struct {
		name        string
		transaction *slodomain.SLOTransaction
		result      *sloFanoutResult
		wantErr     string
		wantNil     bool
		assertState func(t *testing.T, state *sloFanoutTransactionState)
	}{
		{
			name:    "nil transaction rejected",
			wantErr: "slo fanout transaction is missing",
		},
		{
			name:        "missing dispatches returns nil state",
			transaction: mustNewFanoutRunningTransaction(t, now),
			result:      &sloFanoutResult{},
			wantNil:     true,
		},
		{
			name:        "wrong transaction status rejected",
			transaction: mustNewValidatedTransaction(t, now),
			result: &sloFanoutResult{
				Dispatches: []sloFanoutDispatch{{Participant: baseParticipant("https://sp-a.example.com", "id-req-a")}},
			},
			wantErr: "must be in status fanout_running",
		},
		{
			name:        "missing request id rejected",
			transaction: mustNewFanoutRunningTransaction(t, now),
			result: &sloFanoutResult{
				Dispatches: []sloFanoutDispatch{{Participant: baseParticipant("https://sp-a.example.com", "  ")}},
			},
			wantErr: "request id is missing",
		},
		{
			name:        "duplicate request id rejected",
			transaction: mustNewFanoutRunningTransaction(t, now),
			result: &sloFanoutResult{
				Dispatches: []sloFanoutDispatch{
					{Participant: baseParticipant("https://sp-a.example.com", "id-req-dup")},
					{Participant: baseParticipant("https://sp-b.example.com", "id-req-dup")},
				},
			},
			wantErr: "duplicate slo fanout request id",
		},
		{
			name: "state built with pre counts",
			transaction: mustNewFanoutRunningTransactionWithParticipants(t, now, []slodomain.SLOParticipant{
				baseParticipant("https://sp-a.example.com", "id-req-a"),
				baseParticipant("https://sp-b.example.com", "id-req-b"),
				baseParticipant("https://sp-c.example.com", "id-req-c"),
			}),
			result: &sloFanoutResult{
				Dispatches: []sloFanoutDispatch{
					{Participant: baseParticipant("https://sp-a.example.com", "id-req-a")},
					{Participant: baseParticipant("https://sp-b.example.com", "id-req-b")},
				},
				Failures: []sloFanoutFailure{{EntityID: "https://sp-x.example.com"}},
			},
			assertState: func(t *testing.T, state *sloFanoutTransactionState) {
				t.Helper()

				if !assert.NotNil(t, state) {
					return
				}

				assert.Equal(t, 2, len(state.Pending))
				assert.Equal(t, 1, state.PreSuccessCount)
				assert.Equal(t, 1, state.PreFailureCount)
				assert.Equal(t, now, state.UpdatedAt)
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			state, err := newSLOFanoutTransactionState(tc.transaction, tc.result, now)
			if tc.wantErr != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)

				return
			}

			if !assert.NoError(t, err) {
				return
			}

			if tc.wantNil {
				assert.Nil(t, state)

				return
			}

			if tc.assertState != nil {
				tc.assertState(t, state)
			}
		})
	}
}

func TestSLOFanoutTransactionState_OutcomeCounts(t *testing.T) {
	state := &sloFanoutTransactionState{
		PreSuccessCount: 2,
		PreFailureCount: 1,
		Outcomes: map[string]sloFanoutParticipantOutcome{
			"id-1": {Successful: true},
			"id-2": {Successful: false},
		},
	}

	successCount, failureCount := state.outcomeCounts()
	assert.Equal(t, 3, successCount)
	assert.Equal(t, 2, failureCount)

	successCount, failureCount = (*sloFanoutTransactionState)(nil).outcomeCounts()
	assert.Equal(t, 0, successCount)
	assert.Equal(t, 0, failureCount)
}

func TestAggregateSLOFanoutTerminalStatus(t *testing.T) {
	testCases := []struct {
		name         string
		successCount int
		failureCount int
		want         slodomain.SLOStatus
	}{
		{name: "done", successCount: 2, failureCount: 0, want: slodomain.SLOStatusDone},
		{name: "failed", successCount: 0, failureCount: 2, want: slodomain.SLOStatusFailed},
		{name: "partial", successCount: 1, failureCount: 1, want: slodomain.SLOStatusPartial},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			status := aggregateSLOFanoutTerminalStatus(tc.successCount, tc.failureCount)
			assert.Equal(t, tc.want, status)
		})
	}
}

func mustNewValidatedTransaction(t *testing.T, now time.Time) *slodomain.SLOTransaction {
	t.Helper()

	tx, err := slodomain.NewTransaction(
		"tx-test",
		"id-root-request",
		slodomain.SLODirectionIDPInitiated,
		slodomain.SLOBindingRedirect,
		now,
	)
	if err != nil {
		t.Fatalf("cannot create transaction: %v", err)
	}

	if err = tx.TransitionTo(slodomain.SLOStatusValidated, now); err != nil {
		t.Fatalf("cannot transition to validated: %v", err)
	}

	return tx
}

func mustNewFanoutRunningTransaction(t *testing.T, now time.Time) *slodomain.SLOTransaction {
	t.Helper()

	return mustNewFanoutRunningTransactionWithParticipants(t, now, nil)
}

func mustNewFanoutRunningTransactionWithParticipants(
	t *testing.T,
	now time.Time,
	participants []slodomain.SLOParticipant,
) *slodomain.SLOTransaction {
	t.Helper()

	tx := mustNewValidatedTransaction(t, now)
	if err := tx.TransitionTo(slodomain.SLOStatusLocalDone, now); err != nil {
		t.Fatalf("cannot transition to local_done: %v", err)
	}

	if err := tx.TransitionTo(slodomain.SLOStatusFanoutRunning, now); err != nil {
		t.Fatalf("cannot transition to fanout_running: %v", err)
	}

	tx.Participants = participants

	return tx
}
