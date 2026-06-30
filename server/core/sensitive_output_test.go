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

package core

import "testing"

func TestIsSensitiveOutputAttributeMatchesCamelCaseSecrets(t *testing.T) {
	tests := []string{
		"userPassword",
		"clientSecret",
		"refreshToken",
		"privateKey",
		"apiToken",
		"totpSecret",
	}

	for _, attributeName := range tests {
		t.Run(attributeName, func(t *testing.T) {
			if !IsSensitiveOutputAttribute(attributeName) {
				t.Fatalf("IsSensitiveOutputAttribute(%q) = false, want true", attributeName)
			}
		})
	}
}

func TestIsSensitiveOutputAttributePreservesPublicCamelCaseNames(t *testing.T) {
	tests := []string{
		"displayName",
		"givenName",
		"mailPrimaryAddress",
	}

	for _, attributeName := range tests {
		t.Run(attributeName, func(t *testing.T) {
			if IsSensitiveOutputAttribute(attributeName) {
				t.Fatalf("IsSensitiveOutputAttribute(%q) = true, want false", attributeName)
			}
		})
	}
}
