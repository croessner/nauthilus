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

package util

import (
	"encoding/base64"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
)

// helper to generate encoded payload for given algorithm and option
func genPayload(t *testing.T, plain string, salt []byte, alg definitions.Algorithm, opt definitions.PasswordOption) (encoded string) {
	t.Helper()

	cp := &CryptPassword{}

	enc, err := cp.Generate(plain, salt, alg, opt)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	return enc
}

func TestGetParameters_PositiveRegexCases(t *testing.T) {
	plain := "password"
	salt := []byte("NaClSalt")

	tests := []struct {
		name   string
		prefix string
		alg    definitions.Algorithm
		opt    definitions.PasswordOption
	}{
		{"256 default B64 without suffix", "{SSHA256}", definitions.SSHA256, definitions.ENCB64},
		{"256 explicit B64 suffix", "{SSHA256.B64}", definitions.SSHA256, definitions.ENCB64},
		{"256 HEX suffix", "{SSHA256.HEX}", definitions.SSHA256, definitions.ENCHEX},
		{"512 default B64 without suffix", "{SSHA512}", definitions.SSHA512, definitions.ENCB64},
		{"512 explicit B64 suffix", "{SSHA512.B64}", definitions.SSHA512, definitions.ENCB64},
		{"512 HEX suffix", "{SSHA512.HEX}", definitions.SSHA512, definitions.ENCHEX},
	}

	for _, tt := range tests {
		opt := tt.opt
		encoded := genPayload(t, plain, salt, tt.alg, opt)
		full := tt.prefix + encoded

		var cp CryptPassword

		retsalt, alg, pwopt, err := cp.GetParameters(full)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tt.name, err)
		}

		if alg != tt.alg {
			t.Errorf("%s: expected alg %v, got %v", tt.name, tt.alg, alg)
		}

		if pwopt != tt.opt {
			t.Errorf("%s: expected opt %v, got %v", tt.name, tt.opt, pwopt)
		}

		if cp.Password != encoded {
			t.Errorf("%s: expected payload to equal encoded, got different", tt.name)
		}

		if string(retsalt) != string(salt) {
			t.Errorf("%s: expected salt %x, got %x", tt.name, salt, retsalt)
		}
	}
}

func TestGetParameters_NegativeRegexCases(t *testing.T) {
	plain := "password"
	salt := []byte("NaClSalt")

	// valid encoded for reuse
	b64 := genPayload(t, plain, salt, definitions.SSHA256, definitions.ENCB64)
	hexEnc := genPayload(t, plain, salt, definitions.SSHA256, definitions.ENCHEX)

	tests := []struct {
		name  string
		input string
	}{
		{"missing opening brace", "SSHA256.B64}" + b64},
		{"unsupported alg", "{SSHA1024}" + b64},
		{"unsupported option BIN (regex no-match)", "{SSHA256.BIN}" + b64},
		{"malformed base64 payload", "{SSHA256}" + b64 + "*"},
	}

	for _, tt := range tests {
		var cp CryptPassword

		_, _, _, err := cp.GetParameters(tt.input)
		if err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}

	// malformed hex payload
	{
		var cp CryptPassword

		_, _, _, err := cp.GetParameters("{SSHA256.HEX}" + hexEnc + "GG")
		if err == nil {
			t.Errorf("malformed hex payload: expected error")
		}
	}
}

func TestGetParameters_ShortDecodedLength(t *testing.T) {
	plain := "password"
	// empty salt leads to too short decoded buffer for both algs
	emptySalt := []byte("")

	b64256 := genPayload(t, plain, emptySalt, definitions.SSHA256, definitions.ENCB64)
	b64512 := genPayload(t, plain, emptySalt, definitions.SSHA512, definitions.ENCB64)

	// ensure our assumption about decode length holds (32 and 64 respectively)
	if dec, err := base64.StdEncoding.DecodeString(b64256); err != nil || len(dec) != 32 {
		t.Fatalf("unexpected 256 decode length: %v len=%d", err, len(dec))
	}

	if dec, err := base64.StdEncoding.DecodeString(b64512); err != nil || len(dec) != 64 {
		t.Fatalf("unexpected 512 decode length: %v len=%d", err, len(dec))
	}

	cases := []string{
		"{SSHA256}" + b64256,
		"{SSHA512}" + b64512,
	}

	for _, input := range cases {
		var cp CryptPassword

		_, _, _, err := cp.GetParameters(input)
		if err == nil {
			t.Errorf("expected error for short decoded length, got nil for input %s", input)
		}
	}
}

func TestComparePasswords(t *testing.T) {
	var testCases = []struct {
		Name            string
		HashedPassword  string
		PlainPassword   string
		ExpectedOutcome bool
		ExpectingError  bool
	}{
		{
			"matching password ARGON2",
			"$argon2id$v=19$m=65536,t=2,p=1$gCxez+B/Sr5ogq0o+y+7Ig$hKxxLmCF5pMVjcBk+seY7DeLx6RBfNoD/LUg1VZjAuo",
			"abc123",
			true,
			false,
		},
		{
			"non-matching password ARGON2",
			"$argon2id$v=19$m=65536,t=2,p=1$gCxez+B/Sr5ogq0o+y+7Ig$hKxxLmCF5pMVjcBk+seY7DeLx6RBfNoD/LUg1VZjAuo",
			"abc124",
			false,
			false,
		},
		{
			"invalid format",
			"{QWE}123",
			"abc123",
			false,
			true,
		},
		{
			"matching password SSHA256",
			"{SSHA256}9BT0VNzrkTp51/skOYDjOEFoYPN9FoGx/Gd+njZv5tEOgtl6TvODXg==",
			"bc123",
			true,
			false,
		},
		{
			"non-matching password SSHA256.B64",
			"{SSHA256.B64}9BT0VNzrkTp51/skOYDjOEFoYPN9FoGx/Gd+njZv5tEOgtl6TvODXg==",
			"bc120",
			false,
			false,
		},
		{
			"invalid format suffix not supported",
			"{SSHA256.BIN}9BT0VNzrkTp51/skOYDjOEFoYPN9FoGx/Gd+njZv5tEOgtl6TvODXg==",
			"bc123",
			false,
			true,
		},
		{
			"empty hashed password",
			"",
			"abc123",
			false,
			true,
		},
		{
			"empty plain password",
			"$argon2id$v=19$m=65536,t=2,p=1$gCxez+B/Sr5ogq0o+y+7Ig$hKxxLmCF5pMVjcBk+seY7DeLx6RBfNoD/LUg1VZjAuo",
			"",
			false,
			false,
		},
		{
			"empty both password",
			"",
			"",
			false,
			true,
		},
	}

	for _, testCase := range testCases {
		outcome, err := ComparePasswords(testCase.HashedPassword, testCase.PlainPassword)

		if testCase.ExpectingError {
			if err == nil {
				t.Errorf("Expected error but got none for the test case: %s", testCase.Name)
			}
		} else {
			if err != nil {
				t.Errorf("Did not expect error but got one for the test case: %s. Error: %s", testCase.Name, err.Error())
			}

			if outcome != testCase.ExpectedOutcome {
				t.Errorf("Expected outcome '%v' but got '%v' for the test case: %s", testCase.ExpectedOutcome, outcome, testCase.Name)
			}
		}
	}
}
