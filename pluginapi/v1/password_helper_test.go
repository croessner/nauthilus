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

package pluginapi_test

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/pluginapi/v1/password"
)

type testSecret []byte

func (s testSecret) WithBytes(call func([]byte) error) error {
	return call(append([]byte(nil), s...))
}

func (s testSecret) IsZero() bool {
	return len(s) == 0
}

func TestPasswordHelperCompareMatchesServerFixtures(t *testing.T) {
	t.Parallel()

	credential := testSecret("bc123")

	var _ pluginapi.Secret = credential

	matched, err := password.CompareHash("{SSHA256}9BT0VNzrkTp51/skOYDjOEFoYPN9FoGx/Gd+njZv5tEOgtl6TvODXg==", credential)
	if err != nil {
		t.Fatalf("CompareHash() error = %v", err)
	}

	if !matched {
		t.Fatal("CompareHash() = false, want true")
	}

	matched, err = password.CompareHashString(
		"$argon2id$v=19$m=65536,t=2,p=1$gCxez+B/Sr5ogq0o+y+7Ig$hKxxLmCF5pMVjcBk+seY7DeLx6RBfNoD/LUg1VZjAuo",
		"abc124",
	)
	if err != nil {
		t.Fatalf("CompareHashString() error = %v", err)
	}

	if matched {
		t.Fatal("CompareHashString() = true, want false")
	}
}

func TestPasswordHelperGenerateHashMatchesLuaBehavior(t *testing.T) {
	t.Parallel()

	options := password.HashOptions{Nonce: []byte("nonce"), DevMode: false}

	secretHash, err := password.GenerateHash(testSecret("s3cret"), options)
	if err != nil {
		t.Fatalf("GenerateHash() error = %v", err)
	}

	stringHash := password.GenerateHashString("s3cret", options)
	if secretHash != stringHash {
		t.Fatalf("GenerateHash() = %q, want GenerateHashString() = %q", secretHash, stringHash)
	}

	if got := password.GenerateHashString("s3cret", password.HashOptions{Nonce: []byte("nonce"), DevMode: true}); got != stringHash {
		t.Fatalf("dev-mode GenerateHashString() = %q, want canonical hash %q", got, stringHash)
	}
}
