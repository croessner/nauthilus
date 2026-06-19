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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/pluginapi/v1/password"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/gin-gonic/gin"
)

const (
	requestClientIPForwardedHeader = "X-Forwarded-For"
	requestClientIPForwarded       = "203.0.113.10"
	requestClientIPProxy           = "192.168.0.5"
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

func TestPasswordHashHelpersMatchPublicImplementation(t *testing.T) {
	const plainPassword = "s3cret"

	SetDefaultConfigFile(&config.FileSettings{Server: &config.ServerSection{}})
	SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	prepared := PreparePassword(plainPassword)
	got := GetHash(prepared)

	want := password.GenerateHashString(plainPassword, password.HashOptions{})

	if got != want {
		t.Fatalf("GetHash(PreparePassword()) = %q, want public helper %q", got, want)
	}
}

func TestRequestClientIPWithConfigUsesTrustedForwardedFor(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := newRequestClientIPTestContext(t, requestClientIPProxy+":44321", map[string]string{
		requestClientIPForwardedHeader: requestClientIPForwarded,
	})
	cfg := newRequestClientIPTestConfig(requestClientIPProxy)

	if got := RequestClientIPWithConfig(ctx, cfg, nil); got != requestClientIPForwarded {
		t.Fatalf("client IP mismatch: want %q got %q", requestClientIPForwarded, got)
	}
}

func TestRequestClientIPWithConfigIgnoresUntrustedForwardedFor(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := newRequestClientIPTestContext(t, requestClientIPProxy+":44321", map[string]string{
		requestClientIPForwardedHeader: requestClientIPForwarded,
	})
	cfg := newRequestClientIPTestConfig("198.51.100.1")

	if got := RequestClientIPWithConfig(ctx, cfg, nil); got != requestClientIPProxy {
		t.Fatalf("client IP mismatch: want %q got %q", requestClientIPProxy, got)
	}
}

func TestRequestClientIPWithConfigStopsAtUntrustedForwardedHop(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := newRequestClientIPTestContext(t, requestClientIPProxy+":44321", map[string]string{
		requestClientIPForwardedHeader: requestClientIPForwarded + ", 198.51.100.9",
	})
	cfg := newRequestClientIPTestConfig(requestClientIPProxy)

	if got := RequestClientIPWithConfig(ctx, cfg, nil); got != "198.51.100.9" {
		t.Fatalf("client IP mismatch: want %q got %q", "198.51.100.9", got)
	}
}

// newRequestClientIPTestContext builds a Gin context without Gin-level proxy trust.
func newRequestClientIPTestContext(t *testing.T, remoteAddr string, headers map[string]string) *gin.Context {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, engine := gin.CreateTestContext(recorder)

	if err := engine.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies() failed: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	request.RemoteAddr = remoteAddr

	for key, value := range headers {
		request.Header.Set(key, value)
	}

	ctx.Request = request

	return ctx
}

// newRequestClientIPTestConfig returns the proxy trust configuration under test.
func newRequestClientIPTestConfig(trustedProxies ...string) config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{
			TrustedProxies: trustedProxies,
		},
	}
}

func TestGenerateRandomString(t *testing.T) {
	lengths := []int{8, 16, 32, 64}
	for _, l := range lengths {
		s, err := GenerateRandomString(l)
		if err != nil {
			t.Errorf("GenerateRandomString(%d) failed: %v", l, err)
		}
		if len(s) != l {
			t.Errorf("GenerateRandomString(%d) returned string of length %d, expected %d", l, len(s), l)
		}

		s2, _ := GenerateRandomString(l)
		if s == s2 {
			t.Errorf("GenerateRandomString(%d) returned identical strings: %s", l, s)
		}
	}
}
