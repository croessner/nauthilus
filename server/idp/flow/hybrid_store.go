// Copyright (C) 2025 Christian Rößner
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

package flow

import (
	"context"
	"errors"
	"time"
)

const (
	orphanReasonExpired = "expired_state"
	orphanReasonDelete  = "explicit_delete"
)

// HybridStore persists full flow state in a state store and keeps only a reference in a lightweight reference store.
// It can optionally read from legacy storage and migrate old sessions lazily.
type HybridStore struct {
	referenceStore Store
	stateStore     Store
}

// NewHybridStore composes a cookie-based reference store with a primary state store.
func NewHybridStore(referenceStore Store, stateStore Store) *HybridStore {
	return &HybridStore{referenceStore: referenceStore, stateStore: stateStore}
}

// Load resolves a flow ID via reference storage and returns the full state
// from the primary state store.
func (s *HybridStore) Load(ctx context.Context, flowID string) (*State, error) {
	if s == nil {
		return nil, nil
	}

	resolvedFlowID := flowID

	if s.referenceStore != nil {
		referenceState, err := s.referenceStore.Load(ctx, flowID)
		if err != nil {
			reportStoreRead("hybrid_reference", "error")

			return nil, err
		}

		if referenceState != nil {
			reportStoreRead("hybrid_reference", "hit")

			if resolvedFlowID == "" {
				resolvedFlowID = referenceState.FlowID
			}
		} else {
			reportStoreRead("hybrid_reference", "miss")
		}
	}

	if resolvedFlowID == "" {
		return nil, nil
	}

	if s.stateStore != nil {
		state, err := s.stateStore.Load(ctx, resolvedFlowID)
		if err != nil {
			reportStoreRead("hybrid_state", "error")

			return nil, err
		}

		if state != nil {
			reportStoreRead("hybrid_state", "hit")

			return state, nil
		}

		reportStoreRead("hybrid_state", "miss")
		reportStoreTTLExpired("hybrid")

		if err = s.cleanupReference(ctx, resolvedFlowID, orphanReasonExpired); err != nil {
			return nil, err
		}
	}

	return nil, nil
}

// Save writes the full state to the primary store and mirrors a lightweight
// reference into the reference store.
func (s *HybridStore) Save(ctx context.Context, state *State) error {
	if s == nil || state == nil {
		return nil
	}

	if s.stateStore != nil {
		if err := s.stateStore.Save(ctx, state); err != nil {
			reportStoreWrite("hybrid_state", "error")

			return err
		}

		reportStoreWrite("hybrid_state", "ok")
	}

	if s.referenceStore != nil {
		reference := &State{
			FlowID:     state.FlowID,
			GrantType:  state.GrantType,
			FlowType:   state.FlowType,
			Protocol:   state.Protocol,
			Metadata:   state.Metadata,
			PendingMFA: state.PendingMFA,
		}

		if err := s.referenceStore.Save(ctx, reference); err != nil {
			reportStoreWrite("hybrid_reference", "error")

			return err
		}

		reportStoreWrite("hybrid_reference", "ok")
	}

	return nil
}

// Delete removes full state and reference state for a flow.
func (s *HybridStore) Delete(ctx context.Context, flowID string) error {
	if s == nil {
		return nil
	}

	var err error

	if s.stateStore != nil {
		err = errors.Join(err, s.stateStore.Delete(ctx, flowID))
	}

	if s.referenceStore != nil {
		if cleanupErr := s.cleanupReference(ctx, flowID, orphanReasonDelete); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}

	if err != nil {
		reportStoreWrite("hybrid", "error")

		return err
	}

	reportStoreWrite("hybrid", "delete")

	return nil
}

// TouchTTL refreshes TTL across both underlying stores.
func (s *HybridStore) TouchTTL(ctx context.Context, flowID string, ttl time.Duration) error {
	if s == nil {
		return nil
	}

	var err error

	if s.stateStore != nil {
		err = errors.Join(err, s.stateStore.TouchTTL(ctx, flowID, ttl))
	}

	if s.referenceStore != nil {
		err = errors.Join(err, s.referenceStore.TouchTTL(ctx, flowID, ttl))
	}

	if err != nil {
		reportStoreTouchTTL("hybrid", "error")

		return err
	}

	reportStoreTouchTTL("hybrid", "ok")

	return nil
}

func (s *HybridStore) cleanupReference(ctx context.Context, flowID string, reason string) error {
	if s.referenceStore == nil {
		return nil
	}

	if err := s.referenceStore.Delete(ctx, flowID); err != nil {
		reportStoreOrphanCleanup("hybrid", "error")

		return err
	}

	reportStoreOrphanCleanup("hybrid", reason)

	return nil
}
