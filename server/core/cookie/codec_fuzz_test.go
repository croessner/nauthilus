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

package cookie

import (
	"encoding/base64"
	"errors"
	"testing"
)

const (
	fuzzCookieMaxInputBytes = 64 << 10
	fuzzCookieMaxNameBytes  = 1 << 10
)

var fuzzCookieSecret = []byte("synthetic-fuzz-cookie-secret")

func FuzzSecureCodecDecode(f *testing.F) {
	f.Add("session", "")
	f.Add("session", "not-valid-base64")
	f.Add("", "AA")

	f.Fuzz(func(t *testing.T, name string, candidate string) {
		if len(name) > fuzzCookieMaxNameBytes || len(candidate) > fuzzCookieMaxInputBytes {
			return
		}

		codec := NewSecureCodec(fuzzCookieSecret)
		codec.SetMaxAge(0)

		var arbitraryValue []byte

		_ = codec.Decode(name, candidate, &arbitraryValue)

		assertSecureCookieRoundTrip(t, codec, name, []byte(candidate))
	})
}

// assertSecureCookieRoundTrip verifies confidentiality-bound values reject name and payload mutations.
func assertSecureCookieRoundTrip(t *testing.T, codec *SecureCodec, name string, value []byte) {
	t.Helper()

	encoded, err := codec.Encode(name, value)
	if err != nil {
		t.Fatalf("encode fuzz cookie: %v", err)
	}

	var decoded []byte

	if err = codec.Decode(name, encoded, &decoded); err != nil {
		t.Fatalf("decode fuzz cookie: %v", err)
	}

	if string(decoded) != string(value) {
		t.Fatalf("secure cookie round trip changed the value")
	}

	if err = codec.Decode(name+"\x00other", encoded, &decoded); !errors.Is(err, ErrInvalidCookie) {
		t.Fatalf("secure cookie accepted a different cookie name: %v", err)
	}

	tampered := tamperSecureCookie(t, encoded)
	if err = codec.Decode(name, tampered, &decoded); !errors.Is(err, ErrInvalidCookie) {
		t.Fatalf("secure cookie accepted a payload mutation: %v", err)
	}
}

// tamperSecureCookie flips an authenticated payload bit while retaining valid base64url.
func tamperSecureCookie(t *testing.T, encoded string) string {
	t.Helper()

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode generated fuzz cookie: %v", err)
	}

	payload[len(payload)-1] ^= 0x01

	return base64.RawURLEncoding.EncodeToString(payload)
}
