// Copyright (C) 2026 Christian Roessner
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

package pluginapi

import (
	"context"
	"time"
)

// BackendAuthRequest is passed to backend password verification.
type BackendAuthRequest struct {
	Snapshot    RequestSnapshot
	Runtime     RuntimeContext
	Credentials CredentialProvider
	Username    string
}

// AccountListRequest is passed to backend account-list operations.
type AccountListRequest struct {
	Snapshot RequestSnapshot
	Runtime  RuntimeContext
	Username string
}

// AccountListResult describes accounts returned by a backend plugin.
type AccountListResult struct {
	Status   *StatusMessage
	Accounts []string
	Facts    []PolicyFact
}

// Backend verifies credentials and lists accounts for one backend component.
type Backend interface {
	Name() string
	VerifyPassword(context.Context, BackendAuthRequest) (BackendResult, error)
	ListAccounts(context.Context, AccountListRequest) (AccountListResult, error)
}

// TOTPBeginRequest starts a backend-owned TOTP registration flow.
type TOTPBeginRequest struct {
	Snapshot       RequestSnapshot
	Runtime        RuntimeContext
	IdempotencyKey string
	Username       string
}

// TOTPBeginResult returns backend-owned TOTP registration state.
type TOTPBeginResult struct {
	Status                *StatusMessage
	BackendServer         *BackendServerRef
	ExpiresAt             time.Time
	PendingRegistrationID string
	OTPAuthURL            string
}

// TOTPFinishRequest completes a backend-owned TOTP registration flow.
type TOTPFinishRequest struct {
	Snapshot              RequestSnapshot
	Runtime               RuntimeContext
	IdempotencyKey        string
	Username              string
	PendingRegistrationID string
	Code                  string
}

// TOTPFinishResult describes the result of completing TOTP registration.
type TOTPFinishResult struct {
	Status        *StatusMessage
	BackendServer *BackendServerRef
	Verified      bool
}

// TOTPVerifyRequest verifies a TOTP code against a backend.
type TOTPVerifyRequest struct {
	Snapshot RequestSnapshot
	Runtime  RuntimeContext
	Username string
	Code     string
}

// TOTPVerifyResult describes a TOTP verification result.
type TOTPVerifyResult struct {
	Status        *StatusMessage
	BackendServer *BackendServerRef
	Verified      bool
}

// TOTPDeleteRequest removes TOTP state from a backend.
type TOTPDeleteRequest struct {
	Snapshot       RequestSnapshot
	Runtime        RuntimeContext
	IdempotencyKey string
	Username       string
}

// TOTPBackend is implemented by backends that own TOTP operations.
type TOTPBackend interface {
	BeginTOTP(context.Context, TOTPBeginRequest) (TOTPBeginResult, error)
	FinishTOTP(context.Context, TOTPFinishRequest) (TOTPFinishResult, error)
	VerifyTOTP(context.Context, TOTPVerifyRequest) (TOTPVerifyResult, error)
	DeleteTOTP(context.Context, TOTPDeleteRequest) error
}

// RecoveryCodeGenerateRequest asks a backend to generate recovery codes.
type RecoveryCodeGenerateRequest struct {
	Snapshot       RequestSnapshot
	Runtime        RuntimeContext
	IdempotencyKey string
	Username       string
	Count          uint32
}

// RecoveryCodeGenerateResult returns newly generated recovery codes.
type RecoveryCodeGenerateResult struct {
	Status        *StatusMessage
	BackendServer *BackendServerRef
	Codes         []string
}

// RecoveryCodeUseRequest asks a backend to consume one recovery code.
type RecoveryCodeUseRequest struct {
	Snapshot       RequestSnapshot
	Runtime        RuntimeContext
	IdempotencyKey string
	Username       string
	Code           string
}

// RecoveryCodeUseResult describes recovery-code consumption.
type RecoveryCodeUseResult struct {
	Status        *StatusMessage
	BackendServer *BackendServerRef
	Valid         bool
	Remaining     int
}

// RecoveryCodeDeleteRequest asks a backend to remove recovery codes.
type RecoveryCodeDeleteRequest struct {
	Snapshot       RequestSnapshot
	Runtime        RuntimeContext
	IdempotencyKey string
	Username       string
}

// RecoveryCodeBackend is implemented by backends that own TOTP recovery codes.
type RecoveryCodeBackend interface {
	GenerateRecoveryCodes(context.Context, RecoveryCodeGenerateRequest) (RecoveryCodeGenerateResult, error)
	UseRecoveryCode(context.Context, RecoveryCodeUseRequest) (RecoveryCodeUseResult, error)
	DeleteRecoveryCodes(context.Context, RecoveryCodeDeleteRequest) error
}

// WebAuthnCredential carries API-level WebAuthn credential metadata.
type WebAuthnCredential struct {
	LastUsed       time.Time
	ID             []byte
	PublicKey      []byte
	Transports     []string
	AAGUID         string
	Attestation    string
	Authenticator  string
	SignCount      uint32
	BackupState    bool
	BackupEligible bool
}

// WebAuthnListRequest asks a backend for WebAuthn credentials.
type WebAuthnListRequest struct {
	Snapshot RequestSnapshot
	Runtime  RuntimeContext
	Username string
}

// WebAuthnListResult returns WebAuthn credentials.
type WebAuthnListResult struct {
	Status        *StatusMessage
	BackendServer *BackendServerRef
	Credentials   []WebAuthnCredential
}

// WebAuthnSaveRequest asks a backend to save one WebAuthn credential.
type WebAuthnSaveRequest struct {
	Snapshot   RequestSnapshot
	Runtime    RuntimeContext
	Username   string
	Credential WebAuthnCredential
}

// WebAuthnUpdateRequest asks a backend to replace one WebAuthn credential.
type WebAuthnUpdateRequest struct {
	Snapshot      RequestSnapshot
	Runtime       RuntimeContext
	Username      string
	OldCredential WebAuthnCredential
	NewCredential WebAuthnCredential
}

// WebAuthnDeleteRequest asks a backend to delete one WebAuthn credential.
type WebAuthnDeleteRequest struct {
	Snapshot     RequestSnapshot
	Runtime      RuntimeContext
	Username     string
	CredentialID []byte
}

// WebAuthnBackend is implemented by backends that own WebAuthn credentials.
type WebAuthnBackend interface {
	ListWebAuthnCredentials(context.Context, WebAuthnListRequest) (WebAuthnListResult, error)
	SaveWebAuthnCredential(context.Context, WebAuthnSaveRequest) error
	UpdateWebAuthnCredential(context.Context, WebAuthnUpdateRequest) error
	DeleteWebAuthnCredential(context.Context, WebAuthnDeleteRequest) error
}

// PublicMFAStateRequest asks a backend for public MFA metadata.
type PublicMFAStateRequest struct {
	Snapshot        RequestSnapshot
	Runtime         RuntimeContext
	Username        string
	IncludeWebAuthn bool
}

// PublicMFAStateResult contains public MFA metadata safe for identity edges.
type PublicMFAStateResult struct {
	Status              *StatusMessage
	BackendServer       *BackendServerRef
	WebAuthnCredentials []WebAuthnCredential
	RecoveryCodeCount   int
	HasTOTP             bool
	HasWebAuthn         bool
}

// PublicMFAStateBackend is implemented by backends that can read public MFA state.
type PublicMFAStateBackend interface {
	PublicMFAState(context.Context, PublicMFAStateRequest) (PublicMFAStateResult, error)
}
