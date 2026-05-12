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

package grpcauthority

import (
	"context"
	"time"

	commonv1 "github.com/croessner/nauthilus/server/grpcapi/common/v1"
	identityv1 "github.com/croessner/nauthilus/server/grpcapi/identity/v1"
	"github.com/croessner/nauthilus/server/model/mfa"
)

// AuthorityOperation names one authority-side operation for scope and backend-ref checks.
type AuthorityOperation string

// Authority operation constants identify supported authority-side RPC families.
const (
	AuthorityOperationAuthenticate             AuthorityOperation = "authenticate"
	AuthorityOperationLookupIdentity           AuthorityOperation = "lookup_identity"
	AuthorityOperationListAccounts             AuthorityOperation = "list_accounts"
	AuthorityOperationResolveUser              AuthorityOperation = "resolve_user"
	AuthorityOperationGetMFAState              AuthorityOperation = "get_mfa_state"
	AuthorityOperationBeginTOTPRegistration    AuthorityOperation = "begin_totp_registration"
	AuthorityOperationFinishTOTPRegistration   AuthorityOperation = "finish_totp_registration"
	AuthorityOperationVerifyTOTP               AuthorityOperation = "verify_totp"
	AuthorityOperationDeleteTOTP               AuthorityOperation = "delete_totp"
	AuthorityOperationGenerateRecoveryCodes    AuthorityOperation = "generate_recovery_codes"
	AuthorityOperationUseRecoveryCode          AuthorityOperation = "use_recovery_code"
	AuthorityOperationDeleteRecoveryCodes      AuthorityOperation = "delete_recovery_codes"
	AuthorityOperationGetWebAuthnCredentials   AuthorityOperation = "get_webauthn_credentials"
	AuthorityOperationSaveWebAuthnCredential   AuthorityOperation = "save_webauthn_credential"
	AuthorityOperationUpdateWebAuthnCredential AuthorityOperation = "update_webauthn_credential"
	AuthorityOperationDeleteWebAuthnCredential AuthorityOperation = "delete_webauthn_credential"
)

// BackendRefPayload is the Redis-backed authority payload behind an opaque backend reference.
type BackendRefPayload struct {
	IssuedAt           time.Time            `json:"issued_at"`
	ExpiresAt          time.Time            `json:"expires_at"`
	LastUsedAt         time.Time            `json:"last_used_at,omitempty"`
	AllowedOperations  []AuthorityOperation `json:"allowed_operations,omitempty"`
	Type               string               `json:"type"`
	Name               string               `json:"name"`
	Protocol           string               `json:"protocol"`
	Authority          string               `json:"authority"`
	Username           string               `json:"username"`
	Account            string               `json:"account,omitempty"`
	UniqueUserID       string               `json:"unique_user_id,omitempty"`
	DisplayName        string               `json:"display_name,omitempty"`
	ServicePrincipal   string               `json:"service_principal"`
	MTLSClientIdentity string               `json:"mtls_client_identity,omitempty"`
	EdgeClusterID      string               `json:"edge_cluster_id"`
	EdgeInstanceID     string               `json:"edge_instance_id,omitempty"`
	EdgeRequestID      string               `json:"edge_request_id,omitempty"`
	AuthorityRequestID string               `json:"authority_request_id,omitempty"`
	SchemaVersion      int                  `json:"schema_version"`
}

// BackendRefValidation contains request-time bindings that must match the stored payload.
type BackendRefValidation struct {
	Operation          AuthorityOperation
	Username           string
	ServicePrincipal   string
	MTLSClientIdentity string
	EdgeClusterID      string
}

// BackendRefStore issues and validates Redis-backed backend-reference handles.
type BackendRefStore interface {
	Issue(ctx context.Context, payload BackendRefPayload) (*commonv1.BackendRef, error)
	Validate(ctx context.Context, ref *commonv1.BackendRef, validation BackendRefValidation) (*BackendRefPayload, error)
}

// AuthorityIdentityService runs authority-side identity operations behind the transport adapter.
type AuthorityIdentityService interface {
	ResolveUser(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	GetMFAState(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	BeginTOTPRegistration(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	FinishTOTPRegistration(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	VerifyTOTP(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	DeleteTOTP(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	GenerateRecoveryCodes(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	UseRecoveryCode(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	DeleteRecoveryCodes(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	GetWebAuthnCredentials(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	SaveWebAuthnCredential(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	UpdateWebAuthnCredential(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
	DeleteWebAuthnCredential(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error)
}

// AuthorityIdentityInput carries mapped request data into the authority identity service.
type AuthorityIdentityInput struct {
	Context                    *identityv1.RequestContext
	Attributes                 *identityv1.AttributeRequest
	Credential                 *mfa.PersistentCredential
	OldCredential              *mfa.PersistentCredential
	NewCredential              *mfa.PersistentCredential
	Backend                    BackendRefPayload
	Operation                  AuthorityOperation
	Username                   string
	Code                       string
	PendingRegistrationID      string
	IdempotencyKey             string
	CredentialID               []byte
	Count                      uint32
	IncludeMFAState            bool
	IncludeWebAuthnCredentials bool
}

// AuthorityIdentityResult is the domain result returned to the transport adapter.
type AuthorityIdentityResult struct {
	Status                     *commonv1.OperationStatus
	User                       *AuthorityUserSnapshot
	Credentials                []mfa.PersistentCredential
	Backend                    BackendRefPayload
	MFA                        AuthorityMFAState
	ExpiresAt                  time.Time
	PendingRegistrationID      string
	TOTPSecret                 string
	OTPAuthURL                 string
	MissingAttributes          []string
	DeniedAttributes           []string
	RecoveryCodes              []string
	RecoveryCodeCount          uint32
	RemainingRecoveryCodeCount uint32
	Valid                      bool
	Changed                    bool
}

// GetUser returns the released user snapshot.
func (r *AuthorityIdentityResult) GetUser() *AuthorityUserSnapshot {
	if r == nil {
		return nil
	}

	return r.User
}

// GetMFA returns the public MFA state.
func (r *AuthorityIdentityResult) GetMFA() AuthorityMFAState {
	if r == nil {
		return AuthorityMFAState{}
	}

	return r.MFA
}

// GetBackend returns the effective backend-reference payload.
func (r *AuthorityIdentityResult) GetBackend() BackendRefPayload {
	if r == nil {
		return BackendRefPayload{}
	}

	return r.Backend
}

// GetExpiresAt returns the expiry of temporary setup material.
func (r *AuthorityIdentityResult) GetExpiresAt() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.ExpiresAt
}

// GetPendingRegistrationID returns the temporary TOTP registration handle.
func (r *AuthorityIdentityResult) GetPendingRegistrationID() string {
	if r == nil {
		return ""
	}

	return r.PendingRegistrationID
}

// GetTOTPSecret returns one-time TOTP setup material.
func (r *AuthorityIdentityResult) GetTOTPSecret() string {
	if r == nil {
		return ""
	}

	return r.TOTPSecret
}

// GetOTPAuthURL returns the provisioning URI for TOTP setup.
func (r *AuthorityIdentityResult) GetOTPAuthURL() string {
	if r == nil {
		return ""
	}

	return r.OTPAuthURL
}

// GetMissingAttributes returns requested attributes that were unavailable.
func (r *AuthorityIdentityResult) GetMissingAttributes() []string {
	if r == nil {
		return nil
	}

	return r.MissingAttributes
}

// GetDeniedAttributes returns requested attributes that were not released.
func (r *AuthorityIdentityResult) GetDeniedAttributes() []string {
	if r == nil {
		return nil
	}

	return r.DeniedAttributes
}

// GetRecoveryCodes returns newly generated recovery codes.
func (r *AuthorityIdentityResult) GetRecoveryCodes() []string {
	if r == nil {
		return nil
	}

	return r.RecoveryCodes
}

// GetRecoveryCodeCount returns the number of active recovery codes.
func (r *AuthorityIdentityResult) GetRecoveryCodeCount() uint32 {
	if r == nil {
		return 0
	}

	return r.RecoveryCodeCount
}

// GetRemainingRecoveryCodeCount returns the recovery-code count after a use attempt.
func (r *AuthorityIdentityResult) GetRemainingRecoveryCodeCount() uint32 {
	if r == nil {
		return 0
	}

	return r.RemainingRecoveryCodeCount
}

// GetCredentials returns public WebAuthn credential records.
func (r *AuthorityIdentityResult) GetCredentials() []mfa.PersistentCredential {
	if r == nil {
		return nil
	}

	return r.Credentials
}

// GetValid returns the verification result for MFA checks.
func (r *AuthorityIdentityResult) GetValid() bool {
	return r != nil && r.Valid
}

// GetChanged reports whether a mutating operation changed backend state.
func (r *AuthorityIdentityResult) GetChanged() bool {
	return r != nil && r.Changed
}

// AuthorityUserSnapshot contains released identity data for gRPC identity responses.
type AuthorityUserSnapshot struct {
	Attributes   map[string][]string
	Backend      BackendRefPayload
	MFA          AuthorityMFAState
	Username     string
	Account      string
	UniqueUserID string
	DisplayName  string
	Groups       []string
	GroupDNS     []string
}

// AuthorityMFAState contains public MFA state only.
type AuthorityMFAState struct {
	Credentials       []mfa.PersistentCredential
	PreferredMethod   string
	RecoveryCodeCount uint32
	HasTOTP           bool
	HasWebAuthn       bool
}
