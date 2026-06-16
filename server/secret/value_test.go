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

package secret

import (
	"bytes"
	"testing"
)

func TestValueWithBytesInvokesCallbackAndClearsTemporaryBuffer(t *testing.T) {
	value := New("temporary-secret")

	var retained []byte

	value.WithBytes(func(buf []byte) {
		if got, want := string(buf), "temporary-secret"; got != want {
			t.Fatalf("WithBytes() buffer = %q, want %q", got, want)
		}

		retained = buf
	})

	if len(retained) == 0 {
		t.Fatal("WithBytes() did not expose callback bytes")
	}

	if !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatalf("WithBytes() retained buffer = %q, want cleared bytes", string(retained))
	}
}
