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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseScopesFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected []string
	}{
		{
			name:     "unset returns defaults",
			envValue: "",
			expected: defaultScopes,
		},
		{
			name:     "single scope",
			envValue: "openid",
			expected: []string{"openid"},
		},
		{
			name:     "comma separated scopes",
			envValue: "openid,profile,email",
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "comma separated with spaces",
			envValue: "openid, profile, email",
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "whitespace only returns defaults",
			envValue: "   ",
			expected: defaultScopes,
		},
		{
			name:     "trailing comma ignored",
			envValue: "openid,profile,",
			expected: []string{"openid", "profile"},
		},
		{
			name:     "leading comma ignored",
			envValue: ",openid,profile",
			expected: []string{"openid", "profile"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OAUTH2_SCOPES", tt.envValue)

			result := parseScopesFromEnv()

			assert.Equal(t, tt.expected, result)
		})
	}
}
