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
	"fmt"
	"time"
)

var (
	ErrEmptyTransactionID     = errors.New("empty slo transaction id")
	ErrEmptyRootRequestID     = errors.New("empty slo root request id")
	ErrInvalidDirection       = errors.New("invalid slo direction")
	ErrInvalidBinding         = errors.New("invalid slo binding")
	ErrInvalidStatus          = errors.New("invalid slo status")
	ErrEmptyParticipantEntity = errors.New("empty slo participant entity id")
	ErrDuplicateRequestID     = errors.New("duplicate slo request id")
)

// SLOBinding describes the transport binding used for SLO protocol messages.
type SLOBinding string

const (
	SLOBindingUnknown  SLOBinding = "unknown"
	SLOBindingRedirect SLOBinding = "redirect"
	SLOBindingPost     SLOBinding = "post"
)

// Valid reports whether the binding is a known value.
func (b SLOBinding) Valid() bool {
	switch b {
	case SLOBindingRedirect, SLOBindingPost:
		return true
	default:
		return false
	}
}

// SLODirection indicates whether the transaction was initiated by an SP or by the IdP.
type SLODirection string

const (
	SLODirectionUnknown      SLODirection = "unknown"
	SLODirectionSPInitiated  SLODirection = "sp_initiated"
	SLODirectionIDPInitiated SLODirection = "idp_initiated"
)

// Valid reports whether the direction is a known value.
func (d SLODirection) Valid() bool {
	switch d {
	case SLODirectionSPInitiated, SLODirectionIDPInitiated:
		return true
	default:
		return false
	}
}

// SLOStatus represents the lifecycle state of a single logout transaction.
type SLOStatus string

const (
	SLOStatusReceived      SLOStatus = "received"
	SLOStatusValidated     SLOStatus = "validated"
	SLOStatusLocalDone     SLOStatus = "local_done"
	SLOStatusFanoutRunning SLOStatus = "fanout_running"
	SLOStatusDone          SLOStatus = "done"
	SLOStatusPartial       SLOStatus = "partial"
	SLOStatusFailed        SLOStatus = "failed"
)

// Valid reports whether the status is a known value.
func (s SLOStatus) Valid() bool {
	switch s {
	case SLOStatusReceived,
		SLOStatusValidated,
		SLOStatusLocalDone,
		SLOStatusFanoutRunning,
		SLOStatusDone,
		SLOStatusPartial,
		SLOStatusFailed:
		return true
	default:
		return false
	}
}

// IsTerminal reports whether the status marks a completed transaction.
func (s SLOStatus) IsTerminal() bool {
	switch s {
	case SLOStatusDone, SLOStatusPartial, SLOStatusFailed:
		return true
	default:
		return false
	}
}

// CanTransitionTo reports whether moving from the current state to next is allowed.
func (s SLOStatus) CanTransitionTo(next SLOStatus) bool {
	if !s.Valid() || !next.Valid() {
		return false
	}

	switch s {
	case SLOStatusReceived:
		return next == SLOStatusValidated
	case SLOStatusValidated:
		return next == SLOStatusLocalDone
	case SLOStatusLocalDone:
		return next == SLOStatusFanoutRunning
	case SLOStatusFanoutRunning:
		return next == SLOStatusDone || next == SLOStatusPartial || next == SLOStatusFailed
	default:
		return false
	}
}

// TransitionError reports invalid lifecycle transitions.
type TransitionError struct {
	From SLOStatus
	To   SLOStatus
}

// Error returns the transition violation.
func (e TransitionError) Error() string {
	return "invalid slo transition: from=" + string(e.From) + " to=" + string(e.To)
}

// SLOParticipant stores correlation context for a participant service provider.
type SLOParticipant struct {
	EntityID     string     `json:"entity_id"`
	NameID       string     `json:"name_id,omitzero"`
	SessionIndex string     `json:"session_index,omitzero"`
	RequestID    string     `json:"request_id,omitzero"`
	Binding      SLOBinding `json:"binding"`
}

// Validate ensures the participant can be used in a transaction.
func (p *SLOParticipant) Validate() error {
	if p == nil || p.EntityID == "" {
		return fmt.Errorf("slo participant: %w", ErrEmptyParticipantEntity)
	}

	if !p.Binding.Valid() {
		return fmt.Errorf("slo participant: %w (%s)", ErrInvalidBinding, p.Binding)
	}

	return nil
}

// SLOTransaction models one end-to-end SLO run.
//
// Request correlation is defined as:
// 1. RootRequestID for the inbound SLO request that opened the transaction.
// 2. Per-participant RequestID for outbound fanout requests, unique within the transaction.
type SLOTransaction struct {
	TransactionID string           `json:"transaction_id"`
	RootRequestID string           `json:"root_request_id"`
	Account       string           `json:"account,omitzero"`
	Direction     SLODirection     `json:"direction"`
	Binding       SLOBinding       `json:"binding"`
	Status        SLOStatus        `json:"status"`
	Participants  []SLOParticipant `json:"participants,omitzero"`
	CreatedAt     time.Time        `json:"created_at,omitzero"`
	UpdatedAt     time.Time        `json:"updated_at,omitzero"`
	CompletedAt   time.Time        `json:"completed_at,omitzero"`
}

// NewTransaction creates a validated SLO transaction with the initial lifecycle state.
func NewTransaction(transactionID, rootRequestID string, direction SLODirection, binding SLOBinding, now time.Time) (*SLOTransaction, error) {
	tx := &SLOTransaction{
		TransactionID: transactionID,
		RootRequestID: rootRequestID,
		Direction:     direction,
		Binding:       binding,
		Status:        SLOStatusReceived,
		CreatedAt:     now.UTC(),
		UpdatedAt:     now.UTC(),
	}

	if err := tx.Validate(); err != nil {
		return nil, err
	}

	return tx, nil
}

// Normalize fills canonical defaults for optional in-memory fields.
func (t *SLOTransaction) Normalize(now time.Time) {
	if t == nil {
		return
	}

	if t.Status == "" {
		t.Status = SLOStatusReceived
	}

	if t.CreatedAt.IsZero() {
		t.CreatedAt = now.UTC()
	}

	t.UpdatedAt = now.UTC()
}

// Validate ensures the transaction is internally consistent.
func (t *SLOTransaction) Validate() error {
	if t == nil || t.TransactionID == "" {
		return fmt.Errorf("slo transaction: %w", ErrEmptyTransactionID)
	}

	if t.RootRequestID == "" {
		return fmt.Errorf("slo transaction: %w", ErrEmptyRootRequestID)
	}

	if !t.Direction.Valid() {
		return fmt.Errorf("slo transaction: %w (%s)", ErrInvalidDirection, t.Direction)
	}

	if !t.Binding.Valid() {
		return fmt.Errorf("slo transaction: %w (%s)", ErrInvalidBinding, t.Binding)
	}

	if !t.Status.Valid() {
		return fmt.Errorf("slo transaction: %w (%s)", ErrInvalidStatus, t.Status)
	}

	requestIDs := map[string]struct{}{
		t.RootRequestID: {},
	}

	for index := range t.Participants {
		participant := &t.Participants[index]

		if err := participant.Validate(); err != nil {
			return err
		}

		if participant.RequestID == "" {
			continue
		}

		if _, exists := requestIDs[participant.RequestID]; exists {
			return fmt.Errorf("slo transaction: %w (%s)", ErrDuplicateRequestID, participant.RequestID)
		}

		requestIDs[participant.RequestID] = struct{}{}
	}

	return nil
}

// TransitionTo applies a lifecycle transition and updates timestamps.
func (t *SLOTransaction) TransitionTo(next SLOStatus, now time.Time) error {
	if t == nil || t.TransactionID == "" {
		return fmt.Errorf("slo transaction: %w", ErrEmptyTransactionID)
	}

	if !next.Valid() {
		return fmt.Errorf("slo transaction: %w (%s)", ErrInvalidStatus, next)
	}

	if t.Status == "" {
		t.Status = SLOStatusReceived
	}

	if !t.Status.Valid() {
		return fmt.Errorf("slo transaction: %w (%s)", ErrInvalidStatus, t.Status)
	}

	if t.Status == next {
		t.UpdatedAt = now.UTC()

		if next.IsTerminal() && t.CompletedAt.IsZero() {
			t.CompletedAt = now.UTC()
		}

		return nil
	}

	if !t.Status.CanTransitionTo(next) {
		return TransitionError{From: t.Status, To: next}
	}

	t.Status = next
	t.UpdatedAt = now.UTC()

	if next.IsTerminal() {
		t.CompletedAt = now.UTC()
	}

	return nil
}

// CorrelatesRequestID reports whether a request ID belongs to this transaction.
func (t *SLOTransaction) CorrelatesRequestID(requestID string) bool {
	if t == nil || requestID == "" {
		return false
	}

	if t.RootRequestID == requestID {
		return true
	}

	for index := range t.Participants {
		if t.Participants[index].RequestID == requestID {
			return true
		}
	}

	return false
}

// ParticipantByRequestID resolves the participant for a correlated request ID.
func (t *SLOTransaction) ParticipantByRequestID(requestID string) (*SLOParticipant, bool) {
	if t == nil || requestID == "" {
		return nil, false
	}

	for index := range t.Participants {
		if t.Participants[index].RequestID == requestID {
			return &t.Participants[index], true
		}
	}

	return nil, false
}
