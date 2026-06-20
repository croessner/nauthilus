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

package slo

import (
	"errors"
	"testing"
	"time"
)

func TestSLOStatusTransitions(t *testing.T) {
	tests := []struct {
		name string
		from Status
		to   Status
		want bool
	}{
		{name: "received to validated", from: SLOStatusReceived, to: SLOStatusValidated, want: true},
		{name: "validated to local_done", from: SLOStatusValidated, to: SLOStatusLocalDone, want: true},
		{name: "local_done to fanout_running", from: SLOStatusLocalDone, to: SLOStatusFanoutRunning, want: true},
		{name: "fanout_running to done", from: SLOStatusFanoutRunning, to: SLOStatusDone, want: true},
		{name: "fanout_running to partial", from: SLOStatusFanoutRunning, to: SLOStatusPartial, want: true},
		{name: "fanout_running to failed", from: SLOStatusFanoutRunning, to: SLOStatusFailed, want: true},
		{name: "received to failed invalid", from: SLOStatusReceived, to: SLOStatusFailed, want: false},
		{name: "validated to fanout_running invalid", from: SLOStatusValidated, to: SLOStatusFanoutRunning, want: false},
		{name: "done to partial invalid", from: SLOStatusDone, to: SLOStatusPartial, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.from.CanTransitionTo(tc.to); got != tc.want {
				t.Fatalf("CanTransitionTo(%s->%s)=%v want %v", tc.from, tc.to, got, tc.want)
			}
		})
	}
}

func TestSLOTransactionTransitionLifecycle(t *testing.T) {
	now := time.Date(2026, time.March, 18, 10, 0, 0, 0, time.UTC)

	tx, err := NewTransaction("tx-1", "_req-root", SLODirectionSPInitiated, SLOBindingRedirect, now)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	steps := []Status{
		SLOStatusValidated,
		SLOStatusLocalDone,
		SLOStatusFanoutRunning,
		SLOStatusDone,
	}

	for index, step := range steps {
		err = tx.TransitionTo(step, now.Add(time.Duration(index+1)*time.Second))
		if err != nil {
			t.Fatalf("unexpected transition error to %s: %v", step, err)
		}

		if tx.Status != step {
			t.Fatalf("status mismatch: got %s want %s", tx.Status, step)
		}
	}

	if tx.CompletedAt.IsZero() {
		t.Fatal("expected completed_at to be set for terminal status")
	}
}

func TestSLOTransactionTransitionInvalid(t *testing.T) {
	now := time.Date(2026, time.March, 18, 10, 0, 0, 0, time.UTC)

	tx, err := NewTransaction("tx-2", "_req-root", SLODirectionIDPInitiated, SLOBindingPost, now)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	err = tx.TransitionTo(SLOStatusDone, now.Add(time.Second))
	if err == nil {
		t.Fatal("expected invalid transition error")
	}

	if _, ok := errors.AsType[TransitionError](err); !ok {
		t.Fatalf("expected TransitionError, got %T (%v)", err, err)
	}
}

func TestSLOTransactionValidate(t *testing.T) {
	now := time.Date(2026, time.March, 18, 10, 0, 0, 0, time.UTC)

	for _, tc := range sloTransactionValidateCases(now) {
		t.Run(tc.name, func(t *testing.T) {
			assertSLOTransactionValidate(t, tc)
		})
	}
}

type sloTransactionValidateCase struct {
	name    string
	tx      *Transaction
	errWant error
}

// sloTransactionValidateCases returns transaction validation scenarios.
func sloTransactionValidateCases(now time.Time) []sloTransactionValidateCase {
	return append(validSLOTransactionValidateCases(now), invalidSLOTransactionValidateCases()...)
}

// validSLOTransactionValidateCases returns successful transaction validation scenarios.
func validSLOTransactionValidateCases(now time.Time) []sloTransactionValidateCase {
	return []sloTransactionValidateCase{
		{
			name: "valid transaction",
			tx: &Transaction{
				TransactionID: "tx-ok",
				RootRequestID: "_root",
				Direction:     SLODirectionSPInitiated,
				Binding:       SLOBindingRedirect,
				Status:        SLOStatusReceived,
				Participants: []Participant{
					{
						EntityID:  "https://sp1.example.com",
						RequestID: "_sp1",
						Binding:   SLOBindingRedirect,
					},
					{
						EntityID:  "https://sp2.example.com",
						RequestID: "_sp2",
						Binding:   SLOBindingPost,
					},
				},
				CreatedAt: now,
				UpdatedAt: now,
			},
			errWant: nil,
		},
	}
}

// invalidSLOTransactionValidateCases returns failing transaction validation scenarios.
func invalidSLOTransactionValidateCases() []sloTransactionValidateCase {
	return []sloTransactionValidateCase{
		{
			name: "empty transaction id",
			tx: &Transaction{
				RootRequestID: "_root",
				Direction:     SLODirectionSPInitiated,
				Binding:       SLOBindingRedirect,
				Status:        SLOStatusReceived,
			},
			errWant: ErrEmptyTransactionID,
		},
		{
			name: "duplicate request id with root",
			tx: &Transaction{
				TransactionID: "tx-dup",
				RootRequestID: "_req",
				Direction:     SLODirectionSPInitiated,
				Binding:       SLOBindingRedirect,
				Status:        SLOStatusReceived,
				Participants: []Participant{
					{
						EntityID:  "https://sp1.example.com",
						RequestID: "_req",
						Binding:   SLOBindingRedirect,
					},
				},
			},
			errWant: ErrDuplicateRequestID,
		},
		{
			name: "invalid status",
			tx: &Transaction{
				TransactionID: "tx-invalid-status",
				RootRequestID: "_root",
				Direction:     SLODirectionSPInitiated,
				Binding:       SLOBindingRedirect,
				Status:        Status("wrong"),
			},
			errWant: ErrInvalidStatus,
		},
	}
}

// assertSLOTransactionValidate verifies one transaction validation result.
func assertSLOTransactionValidate(t *testing.T, tc sloTransactionValidateCase) {
	t.Helper()

	err := tc.tx.Validate()
	if tc.errWant == nil && err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tc.errWant != nil && !errors.Is(err, tc.errWant) {
		t.Fatalf("expected %v, got %v", tc.errWant, err)
	}
}

func TestSLOTransactionRequestCorrelation(t *testing.T) {
	tx := &Transaction{
		TransactionID: "tx-correlation",
		RootRequestID: "_root",
		Direction:     SLODirectionSPInitiated,
		Binding:       SLOBindingRedirect,
		Status:        SLOStatusReceived,
		Participants: []Participant{
			{
				EntityID:  "https://sp1.example.com",
				RequestID: "_sp1",
				Binding:   SLOBindingRedirect,
			},
		},
	}

	if !tx.CorrelatesRequestID("_root") {
		t.Fatal("expected root request id correlation")
	}

	if !tx.CorrelatesRequestID("_sp1") {
		t.Fatal("expected participant request id correlation")
	}

	if tx.CorrelatesRequestID("_missing") {
		t.Fatal("unexpected correlation for missing request id")
	}

	participant, ok := tx.ParticipantByRequestID("_sp1")
	if !ok {
		t.Fatal("expected participant lookup success")
	}

	if participant.EntityID != "https://sp1.example.com" {
		t.Fatalf("unexpected participant entity id: %s", participant.EntityID)
	}
}
