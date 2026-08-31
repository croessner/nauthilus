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

package identitymapper

import (
	"time"

	identityv1 "github.com/croessner/nauthilus/v4/api/identity/v1"
	"github.com/croessner/nauthilus/v4/server/model/mfa"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// PersistentCredentialToProto maps a stored WebAuthn credential to the gRPC contract.
func PersistentCredentialToProto(credential *mfa.PersistentCredential) *identityv1.WebAuthnCredential {
	if credential == nil {
		return nil
	}

	return &identityv1.WebAuthnCredential{
		CredentialId:    append([]byte(nil), credential.ID...),
		PublicKey:       append([]byte(nil), credential.PublicKey...),
		SignCount:       credential.Authenticator.SignCount,
		Transports:      transportsToStrings(credential.Transport),
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
		AttestationType: credential.AttestationType,
		Name:            credential.Name,
		LastUsed:        timestampFromTime(credential.LastUsed),
		RawJson:         credential.RawJSON,
	}
}

// WebAuthnCredentialToPersistent maps the gRPC credential contract to stored state.
func WebAuthnCredentialToPersistent(credential *identityv1.WebAuthnCredential) *mfa.PersistentCredential {
	if credential == nil {
		return nil
	}

	return &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID:              append([]byte(nil), credential.GetCredentialId()...),
			PublicKey:       append([]byte(nil), credential.GetPublicKey()...),
			AttestationType: credential.GetAttestationType(),
			Transport:       stringsToTransports(credential.GetTransports()),
			Flags: webauthn.CredentialFlags{
				BackupEligible: credential.GetBackupEligible(),
				BackupState:    credential.GetBackupState(),
			},
			Authenticator: webauthn.Authenticator{
				SignCount: credential.GetSignCount(),
			},
		},
		Name:     credential.GetName(),
		RawJSON:  credential.GetRawJson(),
		LastUsed: timeFromTimestamp(credential.GetLastUsed()),
	}
}

// transportsToStrings converts WebAuthn transport identifiers to protobuf values.
func transportsToStrings(transports []protocol.AuthenticatorTransport) []string {
	if len(transports) == 0 {
		return nil
	}

	values := make([]string, 0, len(transports))
	for _, transport := range transports {
		values = append(values, string(transport))
	}

	return values
}

// stringsToTransports converts protobuf values to WebAuthn transport identifiers.
func stringsToTransports(values []string) []protocol.AuthenticatorTransport {
	if len(values) == 0 {
		return nil
	}

	transports := make([]protocol.AuthenticatorTransport, 0, len(values))
	for _, value := range values {
		transports = append(transports, protocol.AuthenticatorTransport(value))
	}

	return transports
}

// timestampFromTime omits zero timestamps and converts populated values.
func timestampFromTime(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}

	return timestamppb.New(value)
}

// timeFromTimestamp converts absent protobuf timestamps to the zero time.
func timeFromTimestamp(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return time.Time{}
	}

	return value.AsTime()
}
