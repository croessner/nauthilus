// Copyright (C) 2024 Christian Rößner
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
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/model/mfa"
)

// Done is the value for channels to finish workers
type Done struct{}

// BackendManager defines an interface for managing authentication backends with methods for user authentication and account handling.
type BackendManager interface {
	// PassDB authenticates a user through a password database using the provided AuthState and returns the authentication result.
	PassDB(auth *AuthState) (passDBResult *PassDBResult, err error)

	// AccountDB retrieves a list of user accounts from the backend using the provided authentication state.
	AccountDB(auth *AuthState) (accounts AccountList, err error)

	// AddTOTPSecret adds the specified TOTP secret to the user's authentication state in the backend.
	AddTOTPSecret(auth *AuthState, totp *mfa.TOTPSecret) (err error)

	// DeleteTOTPSecret removes the TOTP secret for the user in the backend.
	DeleteTOTPSecret(auth *AuthState) (err error)

	// AddTOTPRecoveryCodes adds the specified TOTP recovery codes to the user's authentication state in the backend.
	AddTOTPRecoveryCodes(auth *AuthState, recovery *mfa.TOTPRecovery) (err error)

	// DeleteTOTPRecoveryCodes removes all TOTP recovery codes for the user in the backend.
	DeleteTOTPRecoveryCodes(auth *AuthState) (err error)

	// GetWebAuthnCredentials retrieves WebAuthn credentials for the user in the backend.
	GetWebAuthnCredentials(auth *AuthState) (credentials []mfa.PersistentCredential, err error)

	// SaveWebAuthnCredential saves a WebAuthn credential for the user in the backend.
	SaveWebAuthnCredential(auth *AuthState, credential *mfa.PersistentCredential) (err error)

	// DeleteWebAuthnCredential removes a WebAuthn credential for the user in the backend.
	DeleteWebAuthnCredential(auth *AuthState, credential *mfa.PersistentCredential) (err error)

	// UpdateWebAuthnCredential updates an existing WebAuthn credential in the backend.
	UpdateWebAuthnCredential(auth *AuthState, oldCredential *mfa.PersistentCredential, newCredential *mfa.PersistentCredential) (err error)
}

// PublicMFAState contains public MFA metadata that is safe to expose to an IdP edge.
type PublicMFAState struct {
	WebAuthnCredentials []mfa.PersistentCredential
	RecoveryCodeCount   int
	HasTOTP             bool
	HasWebAuthn         bool
}

// PublicMFAStateProvider is implemented by backends that can read public MFA state directly.
type PublicMFAStateProvider interface {
	GetPublicMFAState(auth *AuthState, includeWebAuthn bool) (PublicMFAState, error)
}

// TOTPRegistration contains one-time setup material for a pending TOTP registration.
type TOTPRegistration struct {
	ExpiresAt             time.Time
	PendingRegistrationID string
	Secret                string
	OTPAuthURL            string
}

// RemoteMFAOperations is implemented by backends that delegate MFA operations to an authority.
type RemoteMFAOperations interface {
	BeginTOTPRegistration(auth *AuthState, idempotencyKey string) (TOTPRegistration, error)
	FinishTOTPRegistration(auth *AuthState, pendingRegistrationID string, code string, idempotencyKey string) error
	VerifyTOTP(auth *AuthState, code string) (bool, error)
	DeleteTOTP(auth *AuthState, idempotencyKey string) error
	GenerateRecoveryCodes(auth *AuthState, count uint32, idempotencyKey string) ([]string, error)
	UseRecoveryCode(auth *AuthState, code string, idempotencyKey string) (bool, error)
	DeleteRecoveryCodes(auth *AuthState, idempotencyKey string) error
}

// TOTPRecoveryCodeConsumer consumes a matching recovery code in one backend-owned operation.
type TOTPRecoveryCodeConsumer interface {
	ConsumeTOTPRecoveryCode(auth *AuthState, code string) (valid bool, remaining int, err error)
}

// BackendManagerFactory constructs a backend manager for a backend plugged in from another package.
type BackendManagerFactory func(backendName string, deps AuthDeps) BackendManager

var backendManagerFactories sync.Map

// RegisterBackendManagerFactory registers a backend manager factory.
func RegisterBackendManagerFactory(backendType definitions.Backend, factory BackendManagerFactory) {
	if factory == nil {
		return
	}

	backendManagerFactories.Store(backendType, factory)
}

func backendManagerFromFactory(backendType definitions.Backend, backendName string, deps AuthDeps) BackendManager {
	factory, ok := backendManagerFactories.Load(backendType)
	if !ok {
		return nil
	}

	return factory.(BackendManagerFactory)(backendName, deps)
}

// RemoteBackendRef binds an edge session to an authority-side backend reference.
type RemoteBackendRef struct {
	Type        string
	Name        string
	Protocol    string
	Authority   string
	OpaqueToken string
}

// IsZero reports whether the reference is empty.
func (r RemoteBackendRef) IsZero() bool {
	return r.Type == "" && r.Name == "" && r.Protocol == "" && r.Authority == "" && r.OpaqueToken == ""
}
