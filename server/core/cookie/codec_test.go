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

package cookie

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewSecureCodec(t *testing.T) {
	codec := NewSecureCodec("test-secret")

	assert.NotNil(t, codec)
	assert.Len(t, codec.encKey, 32)
	assert.Len(t, codec.authKey, 32)
	assert.Equal(t, 86400*7, codec.maxAge)
}

func TestSecureCodec_EncodeDecodeString(t *testing.T) {
	codec := NewSecureCodec("test-secret")

	original := "hello world"

	encoded, err := codec.Encode("test_cookie", original)
	if err != nil {
		t.Fatalf("unexpected error encoding: %v", err)
	}

	assert.NotEmpty(t, encoded)

	var decoded string

	err = codec.Decode("test_cookie", encoded, &decoded)
	if err != nil {
		t.Fatalf("unexpected error decoding: %v", err)
	}

	assert.Equal(t, original, decoded)
}

func TestSecureCodec_EncodeDecodeMap(t *testing.T) {
	codec := NewSecureCodec("test-secret")

	original := map[string]any{
		"username":      "testuser",
		"authenticated": true,
		"count":         42,
	}

	encoded, err := codec.Encode("test_cookie", original)
	if err != nil {
		t.Fatalf("unexpected error encoding: %v", err)
	}

	var decoded map[string]any

	err = codec.Decode("test_cookie", encoded, &decoded)
	if err != nil {
		t.Fatalf("unexpected error decoding: %v", err)
	}

	assert.Equal(t, "testuser", decoded["username"])
	assert.Equal(t, true, decoded["authenticated"])
	assert.Equal(t, 42, decoded["count"])
}

func TestSecureCodec_DifferentCookieNames(t *testing.T) {
	codec := NewSecureCodec("test-secret")

	original := "test data"

	encoded, err := codec.Encode("cookie_a", original)
	if err != nil {
		t.Fatalf("unexpected error encoding: %v", err)
	}

	// Decoding with the same name should work.
	var decoded string

	err = codec.Decode("cookie_a", encoded, &decoded)
	if err != nil {
		t.Fatalf("unexpected error decoding with same name: %v", err)
	}

	assert.Equal(t, original, decoded)

	// Decoding with a different name should fail (HMAC verification).
	err = codec.Decode("cookie_b", encoded, &decoded)

	assert.ErrorIs(t, err, ErrInvalidCookie)
}

func TestSecureCodec_DifferentSecrets(t *testing.T) {
	codec1 := NewSecureCodec("secret1")
	codec2 := NewSecureCodec("secret2")

	original := "test data"

	encoded, err := codec1.Encode("test_cookie", original)
	if err != nil {
		t.Fatalf("unexpected error encoding: %v", err)
	}

	// Decoding with a different secret should fail.
	var decoded string

	err = codec2.Decode("test_cookie", encoded, &decoded)

	assert.ErrorIs(t, err, ErrInvalidCookie)
}

func TestSecureCodec_TamperedData(t *testing.T) {
	codec := NewSecureCodec("test-secret")

	original := "test data"

	encoded, err := codec.Encode("test_cookie", original)
	if err != nil {
		t.Fatalf("unexpected error encoding: %v", err)
	}

	// Tamper with the encoded data.
	tampered := encoded[:len(encoded)-2] + "XX"

	var decoded string

	err = codec.Decode("test_cookie", tampered, &decoded)

	assert.Error(t, err)
}

func TestSecureCodec_InvalidBase64(t *testing.T) {
	codec := NewSecureCodec("test-secret")

	var decoded string

	err := codec.Decode("test_cookie", "not-valid-base64!!!", &decoded)

	assert.ErrorIs(t, err, ErrInvalidCookie)
}

func TestSecureCodec_TooShort(t *testing.T) {
	codec := NewSecureCodec("test-secret")

	var decoded string

	// Very short data (less than minimum length).
	err := codec.Decode("test_cookie", "abc", &decoded)

	assert.ErrorIs(t, err, ErrInvalidCookie)
}

func TestSecureCodec_ExpiredCookie(t *testing.T) {
	codec := NewSecureCodec("test-secret")
	codec.SetMaxAge(1) // 1 second

	original := "test data"

	encoded, err := codec.Encode("test_cookie", original)
	if err != nil {
		t.Fatalf("unexpected error encoding: %v", err)
	}

	// Wait for cookie to expire.
	time.Sleep(2 * time.Second)

	var decoded string

	err = codec.Decode("test_cookie", encoded, &decoded)

	assert.ErrorIs(t, err, ErrExpiredCookie)
}

func TestSecureCodec_NoExpiry(t *testing.T) {
	codec := NewSecureCodec("test-secret")
	codec.SetMaxAge(0) // Disable expiry check.

	original := "test data"

	encoded, err := codec.Encode("test_cookie", original)
	if err != nil {
		t.Fatalf("unexpected error encoding: %v", err)
	}

	var decoded string

	err = codec.Decode("test_cookie", encoded, &decoded)
	if err != nil {
		t.Fatalf("unexpected error decoding: %v", err)
	}

	assert.Equal(t, original, decoded)
}

func TestSecureCodec_ComplexTypes(t *testing.T) {
	codec := NewSecureCodec("test-secret")

	original := map[string]any{
		"strings":  []string{"a", "b", "c"},
		"duration": time.Duration(5 * time.Second),
		"time":     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		"nested": map[string]any{
			"key": "value",
		},
	}

	encoded, err := codec.Encode("test_cookie", original)
	if err != nil {
		t.Fatalf("unexpected error encoding: %v", err)
	}

	var decoded map[string]any

	err = codec.Decode("test_cookie", encoded, &decoded)
	if err != nil {
		t.Fatalf("unexpected error decoding: %v", err)
	}

	assert.Equal(t, []string{"a", "b", "c"}, decoded["strings"])
	assert.Equal(t, time.Duration(5*time.Second), decoded["duration"])
}

func TestSecureCodec_UniqueEncodings(t *testing.T) {
	codec := NewSecureCodec("test-secret")

	original := "test data"

	// Encode the same data twice.
	encoded1, err := codec.Encode("test_cookie", original)
	if err != nil {
		t.Fatalf("unexpected error encoding: %v", err)
	}

	encoded2, err := codec.Encode("test_cookie", original)
	if err != nil {
		t.Fatalf("unexpected error encoding: %v", err)
	}

	// Due to random nonce and different timestamps, encodings should differ.
	assert.NotEqual(t, encoded1, encoded2)

	// But both should decode to the same value.
	var decoded1, decoded2 string

	err = codec.Decode("test_cookie", encoded1, &decoded1)
	if err != nil {
		t.Fatalf("unexpected error decoding: %v", err)
	}

	err = codec.Decode("test_cookie", encoded2, &decoded2)
	if err != nil {
		t.Fatalf("unexpected error decoding: %v", err)
	}

	assert.Equal(t, original, decoded1)
	assert.Equal(t, original, decoded2)
}
