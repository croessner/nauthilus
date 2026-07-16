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

package backend

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
)

func TestPositivePasswordCacheSuccessfulWriteHasOneFullHashField(t *testing.T) {
	const fullHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	fields, ok := buildPositiveCacheHashFields(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		"contract-guid",
		&bktype.PositivePasswordCache{Password: fullHash},
		rediscli.NewSecurityManager(secret.New("")),
	)
	if !ok {
		t.Fatal("successful positive cache payload was rejected")
	}

	passwordFields := 0

	for key := range fields {
		if strings.Contains(key, "password") {
			passwordFields++
		}
	}

	if passwordFields != 1 {
		t.Fatalf("positive cache payload has %d password fields, want exactly one", passwordFields)
	}

	value, ok := fields["password"].(string)
	if !ok {
		t.Fatalf("password field type = %T, want string", fields["password"])
	}

	decrypted, err := rediscli.NewSecurityManager(secret.New("")).Decrypt(value)
	if err != nil {
		t.Fatalf("decrypt password field: %v", err)
	}

	if decrypted != fullHash {
		t.Fatalf("stored password hash = %q, want full-only %q", decrypted, fullHash)
	}
}
