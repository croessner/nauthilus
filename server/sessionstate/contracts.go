// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sessionstate defines the durable browser-session ownership and persistence contracts.
package sessionstate

import (
	"context"
	"encoding/json"
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

// Reference binds one record handle to its owning browser session.
type Reference struct {
	Session Handle
	Record  Handle
}

// Versioned is one typed record together with its compare-and-swap revision.
type Versioned[T any] struct {
	Value    T
	Revision Revision
}

// CommitRequest describes one typed revision-checked write without prescribing a Redis encoding.
type CommitRequest[T any] struct {
	Reference        Reference
	ExpectedRevision Revision
	Value            T
	TTL              time.Duration
}

// DeleteRequest describes one revision-checked cleanup operation.
type DeleteRequest struct {
	Reference        Reference
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
	Load(ctx context.Context, reference Reference) (Versioned[T], error)
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
	Session      *CommitRequest[SessionAnchor]
	OIDC         []CommitRequest[OIDCFlow]
	SAML         []CommitRequest[SAMLFlow]
	Enrollment   []CommitRequest[EnrollmentRecord]
	StepUp       []CommitRequest[StepUpRecord]
	Ceremony     []CommitRequest[CeremonyRecord]
	TOTPRecovery []CommitRequest[TOTPRecoveryRecord]
	Logout       []CommitRequest[LogoutIndex]
}

// TransactionReceipt reports the committed anchor revision.
type TransactionReceipt struct {
	Revision Revision
}

// SessionAnchor is the bounded server-side identity and active-flow index for one browser session.
type SessionAnchor struct {
	Record
	SchemaVersion        uint8
	CreatedAt            time.Time
	IdleExpiresAt        time.Time
	AbsoluteExpiresAt    time.Time
	LastTouchedAt        time.Time
	Authenticated        bool
	IdentityReference    string
	Identity             IdentitySummary
	BackendAffinity      BackendAffinitySummary
	MFAIdentityReference string
	MFAIdentity          IdentitySummary
	MFABackendAffinity   BackendAffinitySummary
	Assurance            AssuranceSummary
	RotatedFrom          Handle
	OIDCFlows            []Handle
	SAMLFlows            []Handle
	Enrollments          []Handle
	StepUps              []Handle
	Ceremonies           []Handle
	TOTPRecovery         []Handle
	LogoutIndexes        []Handle
	Revoked              bool
	Tombstone            bool
}

// IdentitySummary is the bounded, non-secret authenticated identity projection used by browser flows.
type IdentitySummary struct {
	Account     string
	Subject     string
	DisplayName string
	Protocol    string
}

// BackendAffinitySummary binds follow-up operations to an authority backend without browser exposure.
type BackendAffinitySummary struct {
	Type        string
	Name        string
	Protocol    string
	Authority   string
	OpaqueToken string
}

// AssuranceSummary is the stable, non-secret MFA assurance shared by protocol flows.
type AssuranceSummary struct {
	Level     int
	Method    string
	Scope     string
	ProvenAt  time.Time
	ExpiresAt time.Time
}

// OIDCFlow identifies one isolated OIDC flow record.
type OIDCFlow struct {
	Record
	Session              Handle
	ParentFlow           Handle
	FlowType             string
	CurrentStep          string
	AuthOutcome          string
	CancelTarget         string
	ReturnTarget         string
	ResumeTarget         string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	PendingMFA           bool
	ClientID             string
	RedirectURI          string
	ResponseType         string
	GrantType            string
	DeviceCode           string
	DeviceUserCodeDigest string
	Scopes               []string
	State                string
	Nonce                string
	Prompt               string
	CodeChallenge        string
	CodeChallengeMethod  string
	ConsentChallenge     string
	ConsentDecision      string
	DelayedResponse      bool
	Authenticated        bool
	AssuranceSatisfied   bool
	Issuable             bool
	Issued               bool
	Consumed             bool
}

// SAMLFlow identifies one isolated SAML flow record.
type SAMLFlow struct {
	Record
	Session            Handle
	ParentFlow         Handle
	FlowType           string
	CurrentStep        string
	AuthOutcome        string
	CancelTarget       string
	ReturnTarget       string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	PendingMFA         bool
	EntityID           string
	RequestID          string
	RequestDigest      string
	RelayState         string
	Destination        string
	OriginalURL        string
	ResumeTarget       string
	Logout             bool
	DelayedResponse    bool
	Authenticated      bool
	EnrollmentComplete bool
	AssuranceSatisfied bool
	Issuable           bool
	Issued             bool
	Consumed           bool
}

// EnrollmentRecord owns one required-factor enrollment state machine.
type EnrollmentRecord struct {
	Record
	Session           Handle
	Flow              Handle
	AccountReference  string
	IdentityReference string
	RequiredMethods   []string
	CompletedMethods  []string
	CurrentStep       string
	Continuation      string
	Completed         bool
}

// StepUpRecord owns one dynamic assurance or self-service proof operation.
type StepUpRecord struct {
	Record
	Session                  Handle
	Flow                     Handle
	AuthOutcome              string
	PendingIdentityReference string
	PendingIdentity          IdentitySummary
	PendingBackendAffinity   BackendAffinitySummary
	SelfServiceOperation     string
	SelfServiceCredentialID  string
	SelfServiceDeviceName    string
	RequestedLevel           int
	SupportedMethods         []string
	ProofMethod              string
	CompletedAt              time.Time
	FreshUntil               time.Time
	Scope                    string
	Completed                bool
}

// CeremonyRecord owns one short-lived single-use WebAuthn operation.
type CeremonyRecord struct {
	Record
	Session           Handle
	Flow              Handle
	IdentityReference string
	Protocol          string
	Kind              string
	Attempt           uint64
	Payload           json.RawMessage
	ConsumedAt        time.Time
}

// TOTPRecoveryRecord owns short-lived TOTP or recovery-code operation state.
type TOTPRecoveryRecord struct {
	Record
	Session           Handle
	Flow              Handle
	AccountReference  string
	IdentityReference string
	OperationID       string
	Kind              string
	PendingMaterial   []byte
	RecoveryCodes     []string
	Generated         bool
	Saved             bool
	RetryCount        uint8
}

// ConsentGrant is one longer-lived OIDC consent bound to a stable identity and client.
type ConsentGrant struct {
	Record
	IdentityReference string
	ClientID          string
	Scopes            []string
	GrantedAt         time.Time
	GrantExpiresAt    time.Time
}

// LogoutIndex is the bounded per-browser list of issued OIDC client sessions.
// It is current-v1 session-owned state and never contains tokens or browser data.
type LogoutIndex struct {
	Record
	Session           Handle
	IdentityReference string
	Account           string
	OIDCClientIDs     []string
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
