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
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/model/mfa"
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

	if got := roundTripped.Authenticator.SignCount; got != persistent.Authenticator.SignCount {
		t.Fatalf("sign count = %d, want %d", got, persistent.Authenticator.SignCount)
	}

	if got := roundTripped.Name; got != persistent.Name {
		t.Fatalf("name = %q, want %q", got, persistent.Name)
	}

	if got := roundTripped.LastUsed; !got.Equal(persistent.LastUsed) {
		t.Fatalf("last used = %s, want %s", got, persistent.LastUsed)
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
