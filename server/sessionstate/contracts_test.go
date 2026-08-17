// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sessionstate

import (
	"context"
	"testing"
	"time"
)

// TestContractCatalogCoversCanonicalRuntimeInvariants keeps every durable session invariant executable.
func TestContractCatalogCoversCanonicalRuntimeInvariants(t *testing.T) {
	t.Parallel()

	want := []Invariant{
		InvariantEnvelopeSize,
		InvariantServerSideOwnership,
		InvariantCrossFlowBinding,
		InvariantProtocolCoexistence,
		InvariantCompareAndSwap,
		InvariantExpiry,
		InvariantFormatRejection,
		InvariantSafeRestart,
		InvariantUniformVersion,
		InvariantFailureAtomicity,
	}

	for _, invariant := range want {
		contract, ok := ContractFor(invariant)
		if !ok {
			t.Fatalf("missing contract for invariant %q", invariant)
		}

		if contract.RuntimeOwner == "" || contract.TestOwner == "" {
			t.Fatalf("incomplete owner mapping for invariant %q: %#v", invariant, contract)
		}
	}
}

// TestLegacyCookieInventoryHasOneFutureOwner prevents ambiguous migration ownership.
func TestLegacyCookieInventoryHasOneFutureOwner(t *testing.T) {
	t.Parallel()

	seen := make(map[string]Owner, len(LegacyCookieInventory()))
	for _, item := range LegacyCookieInventory() {
		if item.Key == "" || item.Owner == "" {
			t.Fatalf("incomplete inventory item: %#v", item)
		}

		if previous, ok := seen[item.Key]; ok {
			t.Fatalf("legacy key %q has owners %q and %q", item.Key, previous, item.Owner)
		}

		seen[item.Key] = item.Owner
	}

	if len(seen) != LegacyCookieKeyCount {
		t.Fatalf("inventory has %d keys, want %d", len(seen), LegacyCookieKeyCount)
	}
}

// TestCanonicalEnvelopeOwnsNoBusinessState fixes the browser boundary before runtime work begins.
func TestCanonicalEnvelopeOwnsNoBusinessState(t *testing.T) {
	t.Parallel()

	for _, item := range LegacyCookieInventory() {
		if item.Owner == OwnerEnvelope {
			t.Fatalf("legacy business key %q must not survive in the canonical envelope", item.Key)
		}
	}
}

type contractClock struct{}

// Now returns a stable test timestamp.
func (contractClock) Now() time.Time { return time.Unix(1, 0) }

type contractHandleGenerator struct{}

// NewHandle returns a stable opaque handle for interface verification.
func (contractHandleGenerator) NewHandle() (Handle, error) { return Handle("opaque"), nil }

type contractRepository struct{}

// Load satisfies the repository read contract.
func (contractRepository) Load(context.Context, Reference) (Versioned[Record], error) {
	return Versioned[Record]{}, nil
}

// Commit satisfies the repository atomic-write contract.
func (contractRepository) Commit(context.Context, CommitRequest[Record]) (Revision, error) {
	return 0, nil
}

// Delete satisfies the repository cleanup contract.
func (contractRepository) Delete(context.Context, DeleteRequest) error { return nil }

type contractMetrics struct{}

// Observe records a bounded contract event.
func (contractMetrics) Observe(Event) {}

// TestTypedBoundariesRemainComposable catches accidental interface widening.
func TestTypedBoundariesRemainComposable(t *testing.T) {
	t.Parallel()

	var _ Clock = contractClock{}

	var _ HandleGenerator = contractHandleGenerator{}

	var _ Repository[Record] = contractRepository{}

	var _ Metrics = contractMetrics{}
}
