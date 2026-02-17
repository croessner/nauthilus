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

package security

import (
	"testing"

	"github.com/croessner/nauthilus/server/secret"
)

func TestManagerEncryptDecryptRoundTrip(t *testing.T) {
	manager := NewManager(secret.New("testsecret12345678"))

	encrypted, err := manager.Encrypt("totp-secret")
	if err != nil {
		t.Fatalf("expected encryption to succeed, got error: %v", err)
	}
	if encrypted == "" {
		t.Fatalf("expected encrypted value to be set")
	}

	decrypted, err := manager.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("expected decryption to succeed, got error: %v", err)
	}
	if decrypted != "totp-secret" {
		t.Fatalf("expected decrypted value to match, got %q", decrypted)
	}
}

func TestManagerEncryptRequiresSecret(t *testing.T) {
	manager := NewManager(secret.New(""))

	if _, err := manager.Encrypt("totp-secret"); err == nil {
		t.Fatalf("expected encryption to fail without secret")
	}
}

func TestManagerDecryptInvalidCiphertext(t *testing.T) {
	manager := NewManager(secret.New("testsecret12345678"))

	if _, err := manager.Decrypt("not-base64"); err == nil {
		t.Fatalf("expected decryption to fail for invalid ciphertext")
	}
}
