// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sessionstate defines the durable browser-session ownership and persistence contracts.
package sessionstate

import (
	"context"
	"time"
)

// Handle is an opaque, non-semantic reference to one server-side record.
type Handle string

// Revision is the monotonic compare-and-swap revision of a server-side record.
type Revision uint64

// Record is the minimal contract fixture used to keep repository boundaries generic.
type Record struct {
	Handle    Handle
	Revision  Revision
	ExpiresAt time.Time
}

// Versioned is one typed record together with its compare-and-swap revision.
type Versioned[T any] struct {
	Value    T
	Revision Revision
}

// CommitRequest describes one typed revision-checked write without prescribing a Redis encoding.
type CommitRequest[T any] struct {
	ExpectedRevision Revision
	Value            T
	TTL              time.Duration
}

// DeleteRequest describes one revision-checked cleanup operation.
type DeleteRequest struct {
	Handle           Handle
	ExpectedRevision Revision
}

// Clock owns wall-clock access for expiry and freshness decisions.
type Clock interface {
	Now() time.Time
}

// HandleGenerator creates cryptographically random opaque references.
type HandleGenerator interface {
	NewHandle() (Handle, error)
}

// Repository is the revision-aware persistence boundary for one typed record family.
type Repository[T any] interface {
	Load(ctx context.Context, handle Handle) (Versioned[T], error)
	Commit(ctx context.Context, request CommitRequest[T]) (Revision, error)
	Delete(ctx context.Context, request DeleteRequest) error
}

// SessionRepository persists the browser session anchor independently from protocol flows.
type SessionRepository interface {
	Repository[SessionAnchor]
}

// OIDCFlowRepository persists OIDC request and response state independently from SAML.
type OIDCFlowRepository interface {
	Repository[OIDCFlow]
}

// SAMLFlowRepository persists SAML request and response state independently from OIDC.
type SAMLFlowRepository interface {
	Repository[SAMLFlow]
}

// Transaction begins one atomic multi-record mutation.
type Transaction interface {
	Commit(ctx context.Context, request TransactionRequest) (TransactionReceipt, error)
}

// TransactionFactory creates transactions bound to one browser session anchor.
type TransactionFactory interface {
	Begin(ctx context.Context, session Handle) (Transaction, error)
}

// TransactionRequest groups typed writes and deletions that must become visible together.
type TransactionRequest struct {
	Session *CommitRequest[SessionAnchor]
	OIDC    []CommitRequest[OIDCFlow]
	SAML    []CommitRequest[SAMLFlow]
	Deletes []DeleteRequest
}

// TransactionReceipt reports the committed anchor revision.
type TransactionReceipt struct {
	Revision Revision
}

// SessionAnchor is the bounded server-side identity and active-flow index for one browser session.
type SessionAnchor struct {
	Record
	OIDCFlows []Handle
	SAMLFlows []Handle
}

// OIDCFlow identifies one isolated OIDC flow record.
type OIDCFlow struct {
	Record
	Session Handle
}

// SAMLFlow identifies one isolated SAML flow record.
type SAMLFlow struct {
	Record
	Session Handle
}

// EventKind is a bounded identifier-free session telemetry classification.
type EventKind string

// Event kinds are the complete bounded telemetry outcome vocabulary.
const (
	EventLoadFailure     EventKind = "load_failure"
	EventCommitFailure   EventKind = "commit_failure"
	EventCleanupFailure  EventKind = "cleanup_failure"
	EventFormatRejection EventKind = "format_rejection"
	EventSafeRestart     EventKind = "safe_restart"
)

// Event is a bounded telemetry event and intentionally carries no raw identifiers.
type Event struct {
	Kind  EventKind
	Owner Owner
}

// Metrics records bounded session lifecycle outcomes.
type Metrics interface {
	Observe(event Event)
}

// Invariant names one architecture property that must remain executable.
type Invariant string

// Invariants are the executable durable browser-session architecture properties.
const (
	InvariantEnvelopeSize        Invariant = "envelope_size"
	InvariantServerSideOwnership Invariant = "server_side_ownership"
	InvariantCrossFlowBinding    Invariant = "cross_flow_binding"
	InvariantProtocolCoexistence Invariant = "protocol_coexistence"
	InvariantCompareAndSwap      Invariant = "compare_and_swap"
	InvariantExpiry              Invariant = "expiry"
	InvariantFormatRejection     Invariant = "format_rejection"
	InvariantSafeRestart         Invariant = "safe_checkpoint_restart"
	InvariantUniformVersion      Invariant = "uniform_version_rollout"
	InvariantFailureAtomicity    Invariant = "failure_atomicity"
)

// Contract maps an invariant to the future runtime and test owners.
type Contract struct {
	Invariant    Invariant
	RuntimeOwner string
	TestOwner    string
}

const (
	envelopeCodecOwner     = "cookie.EnvelopeCodec"
	transactionCommitOwner = "transaction commit"
)

var contracts = map[Invariant]Contract{
	InvariantEnvelopeSize: {
		Invariant: InvariantEnvelopeSize, RuntimeOwner: envelopeCodecOwner, TestOwner: "sessionstate envelope tests",
	},
	InvariantServerSideOwnership: {
		Invariant: InvariantServerSideOwnership, RuntimeOwner: "sessionstate repositories", TestOwner: "sessionstate ownership tests",
	},
	InvariantCrossFlowBinding: {
		Invariant: InvariantCrossFlowBinding, RuntimeOwner: "typed flow repositories", TestOwner: "OIDC and SAML binding tests",
	},
	InvariantProtocolCoexistence: {
		Invariant: InvariantProtocolCoexistence, RuntimeOwner: "session anchor indexes", TestOwner: "parallel protocol flow tests",
	},
	InvariantCompareAndSwap: {
		Invariant: InvariantCompareAndSwap, RuntimeOwner: transactionCommitOwner, TestOwner: "repository CAS tests",
	},
	InvariantExpiry: {
		Invariant: InvariantExpiry, RuntimeOwner: "typed repositories", TestOwner: "repository expiry tests",
	},
	InvariantFormatRejection: {
		Invariant: InvariantFormatRejection, RuntimeOwner: envelopeCodecOwner, TestOwner: "cookie format rejection tests",
	},
	InvariantSafeRestart: {
		Invariant: InvariantSafeRestart, RuntimeOwner: "flow entrypoints", TestOwner: "OIDC SAML and MFA restart tests",
	},
	InvariantUniformVersion: {
		Invariant: InvariantUniformVersion, RuntimeOwner: "deployment contract", TestOwner: "release guardrail",
	},
	InvariantFailureAtomicity: {
		Invariant: InvariantFailureAtomicity, RuntimeOwner: transactionCommitOwner, TestOwner: "save cleanup and response tests",
	},
}

// ContractFor returns the executable ownership mapping for one invariant.
func ContractFor(invariant Invariant) (Contract, bool) {
	contract, ok := contracts[invariant]

	return contract, ok
}
