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

package cborcodec

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"
)

const fuzzCBORMaxInputBytes = 64 << 10

// fuzzCBORRoundTripValue exercises deterministic typed encoding without invalid UTF-8 strings.
type fuzzCBORRoundTripValue struct {
	Text string
	Data []byte
	Size uint32
}

func FuzzCBORDecode(f *testing.F) {
	f.Add([]byte{0xa1, 0x61, 0x61, 0x01})
	f.Add([]byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02})
	f.Add([]byte{0xc0, 0x61, 0x61})
	f.Add([]byte{0x9f, 0x01, 0xff})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzCBORMaxInputBytes {
			return
		}

		assertCBORTypedRoundTrip(t, data)
		assertCBORCanonicalReencoding(t, data)
	})
}

// assertCBORTypedRoundTrip verifies the shared codec preserves supported typed values.
func assertCBORTypedRoundTrip(t *testing.T, data []byte) {
	t.Helper()

	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	original := fuzzCBORRoundTripValue{
		Text: base64.RawURLEncoding.EncodeToString(data),
		Data: dataCopy,
		Size: uint32(len(data)),
	}

	encoded, err := Marshal(original)
	if err != nil {
		t.Fatalf("marshal supported CBOR value: %v", err)
	}

	var decoded fuzzCBORRoundTripValue

	if err = Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal supported CBOR value: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Fatalf("CBOR typed round trip changed the value")
	}
}

// assertCBORCanonicalReencoding verifies accepted arbitrary input has a stable canonical form.
func assertCBORCanonicalReencoding(t *testing.T, data []byte) {
	t.Helper()

	var firstValue any

	if err := Unmarshal(data, &firstValue); err != nil {
		return
	}

	firstCanonical, err := Marshal(firstValue)
	if err != nil {
		t.Fatalf("marshal accepted CBOR value: %v", err)
	}

	var secondValue any

	if err = Unmarshal(firstCanonical, &secondValue); err != nil {
		t.Fatalf("decode canonical CBOR value: %v", err)
	}

	secondCanonical, err := Marshal(secondValue)
	if err != nil {
		t.Fatalf("re-encode canonical CBOR value: %v", err)
	}

	if !bytes.Equal(firstCanonical, secondCanonical) {
		t.Fatalf("accepted CBOR input does not have a stable canonical encoding")
	}
}
