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

package util

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestPasswordHashHelpersUseFullSHA256(t *testing.T) {
	value := []byte("prepared-contract-password")
	wantDigest := sha256.Sum256(value)
	want := hex.EncodeToString(wantDigest[:])

	if got := GetHashBytes(value); got != want {
		t.Fatalf("GetHashBytes() = %q, want full SHA-256 %q", got, want)
	}

	if got := GetHash(string(value)); got != want {
		t.Fatalf("GetHash() = %q, want full SHA-256 %q", got, want)
	}
}
