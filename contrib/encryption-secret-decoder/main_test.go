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

package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/security"
)

func TestDecryptCiphertextUsesNauthilusSecurityManager(t *testing.T) {
	secretBytes := []byte("testsecret12345678")
	manager := security.NewManager(secret.FromBytes(secretBytes))

	encrypted, err := manager.Encrypt("totp-secret")
	if err != nil {
		t.Fatalf("encrypt fixture: %v", err)
	}

	decrypted, err := decryptCiphertext(secretBytes, encrypted)
	if err != nil {
		t.Fatalf("decrypt ciphertext: %v", err)
	}

	if decrypted != "totp-secret" {
		t.Fatalf("decrypted value = %q, want %q", decrypted, "totp-secret")
	}
}

func TestPrintablePlaintextPreservesPrintableUnicode(t *testing.T) {
	input := "TOTP äöü ✓"

	if got := printablePlaintext(input); got != input {
		t.Fatalf("printable plaintext = %q, want %q", got, input)
	}
}

func TestPrintablePlaintextEscapesControlAndBinaryBytes(t *testing.T) {
	input := string([]byte{'A', 0x00, '\n', '\t', '\\', 0xff})
	want := `A\x00\n\t\\\xff`

	if got := printablePlaintext(input); got != want {
		t.Fatalf("printable plaintext = %q, want %q", got, want)
	}
}

func TestCleanCiphertextRejectsWhitespaceOnlyInput(t *testing.T) {
	_, err := cleanCiphertext(" \n\t ")
	if !errors.Is(err, errEmptyCiphertext) {
		t.Fatalf("clean ciphertext error = %v, want %v", err, errEmptyCiphertext)
	}
}

func TestReadCiphertextReaderTrimsPipedInput(t *testing.T) {
	ciphertext, err := readCiphertextReader(bytes.NewBufferString(" abc123\n"))
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	if ciphertext != "abc123" {
		t.Fatalf("ciphertext = %q, want %q", ciphertext, "abc123")
	}
}
