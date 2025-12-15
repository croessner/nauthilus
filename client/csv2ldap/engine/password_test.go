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

package engine

import "testing"

func TestSHAEncoder_Base64(t *testing.T) {
	enc := &SHAEncoder{Encoding: "b64"}
	out, err := enc.Encode("secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ="
	if out != want {
		t.Fatalf("mismatch:\n got: %s\nwant: %s", out, want)
	}
}

func TestSHAEncoder_Hex(t *testing.T) {
	enc := &SHAEncoder{Encoding: "hex"}
	out, err := enc.Encode("secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "{SHA.HEX}e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"
	if out != want {
		t.Fatalf("mismatch:\n got: %s\nwant: %s", out, want)
	}
}
