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

package mfa

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	jsoniter "github.com/json-iterator/go"
)

func TestPersistentCredentialMarshalIncludesSignCount(t *testing.T) {
	credential := PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte{0x01},
			Authenticator: webauthn.Authenticator{
				SignCount: 7,
			},
		},
		Name: "device",
	}

	data, err := jsoniter.ConfigFastest.Marshal(credential)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}

	var raw map[string]any
	if err := jsoniter.ConfigFastest.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal credential to map: %v", err)
	}

	if raw["signCount"] != float64(7) {
		t.Fatalf("expected top-level signCount 7, got %#v", raw["signCount"])
	}

	authenticator, ok := raw["authenticator"].(map[string]any)
	if !ok {
		t.Fatalf("expected authenticator object in JSON")
	}
	if authenticator["signCount"] != float64(7) {
		t.Fatalf("expected authenticator signCount 7, got %#v", authenticator["signCount"])
	}
}

func TestPersistentCredentialUnmarshalLegacySignCount(t *testing.T) {
	data := []byte(`{"id":"AQ==","signCount":9}`)

	var credential PersistentCredential
	if err := jsoniter.ConfigFastest.Unmarshal(data, &credential); err != nil {
		t.Fatalf("unmarshal legacy credential: %v", err)
	}

	if credential.Authenticator.SignCount != 9 {
		t.Fatalf("expected signCount 9, got %d", credential.Authenticator.SignCount)
	}
}
