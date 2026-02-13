// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package config

import (
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/stretchr/testify/assert"
)

func TestBruteForceRule_GetBanTime(t *testing.T) {
	tests := []struct {
		name     string
		rule     *BruteForceRule
		expected time.Duration
	}{
		{
			name:     "nil rule returns default",
			rule:     nil,
			expected: definitions.DefaultBanTime,
		},
		{
			name:     "zero BanTime returns default",
			rule:     &BruteForceRule{Name: "test"},
			expected: definitions.DefaultBanTime,
		},
		{
			name:     "explicit BanTime is returned",
			rule:     &BruteForceRule{Name: "test", BanTime: 2 * time.Hour},
			expected: 2 * time.Hour,
		},
		{
			name:     "large explicit BanTime is returned",
			rule:     &BruteForceRule{Name: "test", BanTime: 24 * time.Hour},
			expected: 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.GetBanTime()

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBruteForceRule_String_IncludesBanTime(t *testing.T) {
	rule := &BruteForceRule{
		Name:           "login_rule",
		Period:         10 * time.Minute,
		BanTime:        4 * time.Hour,
		CIDR:           24,
		FailedRequests: 5,
		IPv4:           true,
	}

	result := rule.String()

	assert.Contains(t, result, "BanTime: 4h0m0s")
	assert.Contains(t, result, "Name: login_rule")
}

func TestBruteForceRule_String_DefaultBanTime(t *testing.T) {
	rule := &BruteForceRule{
		Name:           "test_rule",
		Period:         5 * time.Minute,
		CIDR:           32,
		FailedRequests: 3,
		IPv4:           true,
	}

	result := rule.String()

	assert.Contains(t, result, "BanTime: 8h0m0s")
}
