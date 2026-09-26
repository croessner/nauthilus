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
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// phpPasswordVerifyExample is the bcrypt hash from the PHP password_verify documentation for "rasmuslerdorf".
const phpPasswordVerifyExample = "$2y$10$.vGA1O9wmRjrwAVXD98HNOgsNpDczlqm3Jq7KnEd1rVAGv3Fykk1a"

func TestCompareHashAcceptsPHPBcrypt(t *testing.T) {
	matched, err := CompareHashString(phpPasswordVerifyExample, "rasmuslerdorf")
	if err != nil || !matched {
		t.Fatalf("CompareHashString(PHP $2y$) = %v, %v, want match", matched, err)
	}

	matched, err = CompareHashString(phpPasswordVerifyExample, "rasmuslerdorF")
	if err != nil || matched {
		t.Fatalf("CompareHashString(PHP $2y$, wrong password) = %v, %v, want a clean mismatch", matched, err)
	}
}

func TestCompareHashAcceptsEveryBcryptVersionPrefix(t *testing.T) {
	generated, err := bcrypt.GenerateFromPassword([]byte("bcrypt-contract"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}

	for _, prefix := range []string{"$2a$", "$2b$", "$2y$"} {
		hash := prefix + strings.TrimPrefix(string(generated), "$2a$")

		matched, err := CompareHashString(hash, "bcrypt-contract")
		if err != nil || !matched {
			t.Fatalf("CompareHashString(%s) = %v, %v, want match", prefix, matched, err)
		}

		matched, err = CompareHashString(hash, "bcrypt-contracT")
		if err != nil || matched {
			t.Fatalf("CompareHashString(%s, wrong password) = %v, %v, want a clean mismatch", prefix, matched, err)
		}
	}
}

func TestCompareHashUsesTheFirst72BytesLikeBcrypt(t *testing.T) {
	long := bytes.Repeat([]byte("x"), 80)

	generated, err := bcrypt.GenerateFromPassword(long[:72], bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}

	matched, err := CompareHashBytes(string(generated), long)
	if err != nil || !matched {
		t.Fatalf("CompareHashBytes(80-byte password) = %v, %v, want the bcrypt 72-byte match", matched, err)
	}
}

func TestCompareHashRejectsMalformedBcrypt(t *testing.T) {
	if matched, err := CompareHashString("$2y$10$short", "password"); err == nil || matched {
		t.Fatalf("CompareHashString(malformed bcrypt) = %v, %v, want an error", matched, err)
	}
}
