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

package password

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestGenerateHashUsesFullSHA256(t *testing.T) {
	prepared := PrepareBytes([]byte("contract-password"), []byte("contract-nonce"))
	wantDigest := sha256.Sum256(prepared)
	want := hex.EncodeToString(wantDigest[:])

	if got := GenerateHashBytes([]byte("contract-password"), HashOptions{Nonce: []byte("contract-nonce")}); got != want {
		t.Fatalf("GenerateHashBytes() = %q, want full SHA-256 %q", got, want)
	}
}

func TestDeveloperModeNeverReturnsRawPreparedPassword(t *testing.T) {
	prepared := PrepareBytes([]byte("contract-password"), []byte("contract-nonce"))
	wantDigest := sha256.Sum256(prepared)
	want := hex.EncodeToString(wantDigest[:])
	got := GenerateHashBytes([]byte("contract-password"), HashOptions{Nonce: []byte("contract-nonce"), DevMode: true})

	if got == string(prepared) {
		t.Fatal("developer mode exposed raw prepared password bytes")
	}

	if got != want {
		t.Fatalf("developer-mode GenerateHashBytes() = %q, want full SHA-256 %q", got, want)
	}
}
