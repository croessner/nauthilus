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

package bootfx

import (
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/util"
)

func TestGenerateAdminPasswordHash(t *testing.T) {
	tests := []struct {
		name            string
		password        []byte
		retypedPassword []byte
		wantErr         bool
	}{
		{
			name:            "valid password",
			password:        []byte("Sup3rS3cret!"),
			retypedPassword: []byte("Sup3rS3cret!"),
		},
		{
			name:            "empty password",
			password:        []byte(""),
			retypedPassword: []byte(""),
			wantErr:         true,
		},
		{
			name:            "blank password",
			password:        []byte("   "),
			retypedPassword: []byte("   "),
			wantErr:         true,
		},
		{
			name:            "mismatched password",
			password:        []byte("Sup3rS3cret!"),
			retypedPassword: []byte("Sup3rS3cret?"),
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := GenerateAdminPasswordHash(tt.password, tt.retypedPassword)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !strings.HasPrefix(hash, "$argon2id$") {
				t.Fatalf("expected argon2id hash prefix, got %q", hash)
			}

			match, compareErr := util.ComparePasswords(hash, string(tt.password))
			if compareErr != nil {
				t.Fatalf("compare failed: %v", compareErr)
			}

			if !match {
				t.Fatalf("generated hash does not match original password: %q", hash)
			}
		})
	}
}
