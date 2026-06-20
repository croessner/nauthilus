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

package identityv1

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"google.golang.org/protobuf/proto"
)

func TestWebAuthnCredentialMapperPreservesPersistentCredentialFields(t *testing.T) {
	t.Parallel()

	lastUsed := time.Date(2026, 5, 12, 10, 15, 30, 0, time.UTC)
	persistent := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID:              []byte{0x01, 0x02, 0x03},
			PublicKey:       []byte{0x04, 0x05, 0x06},
			AttestationType: testAttestationTypeNone,
			Transport: []protocol.AuthenticatorTransport{
				protocol.USB,
				protocol.Internal,
			},
			Flags: webauthn.CredentialFlags{
				BackupEligible: true,
				BackupState:    true,
			},
			Authenticator: webauthn.Authenticator{
				SignCount: 42,
			},
		},
		Name:     testCredentialName,
		RawJSON:  testCredentialRawJSON,
		LastUsed: lastUsed,
	}

	message := PersistentCredentialToProto(persistent)

	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}

	var decoded WebAuthnCredential
	if err := proto.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal credential: %v", err)
	}

	roundTripped := WebAuthnCredentialToPersistent(&decoded)

	assertCredentialBytes(t, "credential ID", roundTripped.ID, persistent.ID)
	assertCredentialBytes(t, "public key", roundTripped.PublicKey, persistent.PublicKey)
	assertCredentialAuthenticatorFields(t, roundTripped, persistent)
	assertCredentialMetadataFields(t, roundTripped, persistent)
}

// assertCredentialAuthenticatorFields verifies authenticator and transport fields.
func assertCredentialAuthenticatorFields(t *testing.T, roundTripped *mfa.PersistentCredential, persistent *mfa.PersistentCredential) {
	t.Helper()

	if got := roundTripped.Authenticator.SignCount; got != persistent.Authenticator.SignCount {
		t.Fatalf("sign count = %d, want %d", got, persistent.Authenticator.SignCount)
	}

	if got := roundTripped.Transport; len(got) != 2 || got[0] != protocol.USB || got[1] != protocol.Internal {
		t.Fatalf("transports = %#v, want usb and internal", got)
	}

	if got := roundTripped.Flags.BackupEligible; got != persistent.Flags.BackupEligible {
		t.Fatalf("backup eligible = %v, want %v", got, persistent.Flags.BackupEligible)
	}

	if got := roundTripped.Flags.BackupState; got != persistent.Flags.BackupState {
		t.Fatalf("backup state = %v, want %v", got, persistent.Flags.BackupState)
	}
}

// assertCredentialMetadataFields verifies attestation and metadata fields.
func assertCredentialMetadataFields(t *testing.T, roundTripped *mfa.PersistentCredential, persistent *mfa.PersistentCredential) {
	t.Helper()

	if got := roundTripped.AttestationType; got != persistent.AttestationType {
		t.Fatalf("attestation type = %q, want %q", got, persistent.AttestationType)
	}

	if got := roundTripped.Name; got != persistent.Name {
		t.Fatalf("name = %q, want %q", got, persistent.Name)
	}

	if got := roundTripped.RawJSON; got != persistent.RawJSON {
		t.Fatalf("raw json = %q, want %q", got, persistent.RawJSON)
	}

	if got := roundTripped.LastUsed; !got.Equal(persistent.LastUsed) {
		t.Fatalf("last used = %s, want %s", got, persistent.LastUsed)
	}
}

func TestWebAuthnCredentialMapperPreservesLegacySignCountJSONCompatibility(t *testing.T) {
	t.Parallel()

	const legacyJSON = `{"id":"AQID","publicKey":"BAUG","signCount":7,"name":"Legacy device","lastUsed":"2026-05-12T10:15:30Z"}`

	var persistent mfa.PersistentCredential
	if err := json.Unmarshal([]byte(legacyJSON), &persistent); err != nil {
		t.Fatalf("unmarshal legacy credential: %v", err)
	}

	if got := persistent.Authenticator.SignCount; got != 7 {
		t.Fatalf("legacy signCount = %d, want 7", got)
	}

	roundTripped := WebAuthnCredentialToPersistent(PersistentCredentialToProto(&persistent))
	if got := roundTripped.Authenticator.SignCount; got != 7 {
		t.Fatalf("round-tripped sign count = %d, want 7", got)
	}

	encoded, err := json.Marshal(roundTripped)
	if err != nil {
		t.Fatalf("marshal round-tripped credential: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal marshaled credential: %v", err)
	}

	if got := decoded["signCount"]; got != float64(7) {
		t.Fatalf("marshaled signCount = %#v, want 7", got)
	}
}

func TestWebAuthnCredentialMappersHandleNilInput(t *testing.T) {
	t.Parallel()

	if got := PersistentCredentialToProto(nil); got != nil {
		t.Fatalf("PersistentCredentialToProto(nil) = %#v, want nil", got)
	}

	if got := WebAuthnCredentialToPersistent(nil); got != nil {
		t.Fatalf("WebAuthnCredentialToPersistent(nil) = %#v, want nil", got)
	}
}

func assertCredentialBytes(t *testing.T, name string, got []byte, want []byte) {
	t.Helper()

	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}
