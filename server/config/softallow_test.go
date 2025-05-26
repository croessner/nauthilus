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

package config

import (
	"testing"
)

func TestSoftWhitelist_String(t *testing.T) {
	tests := []struct {
		name string
		s    SoftWhitelist
		want string
	}{
		{"NilSoftWhitelist", nil, "SoftWhitelist: <nil>"},
		{"EmptySoftWhitelist", SoftWhitelist{}, "SoftWhitelist: {SoftWhitelist: <empty>}"},
		{
			"NonEmptySoftWhitelist",
			SoftWhitelist{"user1": {"192.168.1.0/24"}},
			"SoftWhitelist: {SoftWhitelist[user1]: 192.168.1.0/24}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSoftWhitelist_HasSoftWhitelist(t *testing.T) {
	tests := []struct {
		name string
		s    SoftWhitelist
		want bool
	}{
		{"NilSoftWhitelist", nil, false},
		{"EmptySoftWhitelist", SoftWhitelist{}, false},
		{"NonEmptySoftWhitelist", SoftWhitelist{"user1": {"192.168.1.0/24"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.HasSoftWhitelist(); got != tt.want {
				t.Errorf("HasSoftWhitelist() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSoftWhitelist_isValidNetwork(t *testing.T) {
	tests := []struct {
		name    string
		s       SoftWhitelist
		network string
		want    bool
	}{
		{"ValidIPv4CIDR", SoftWhitelist{}, "192.168.1.0/24", true},
		{"InvalidCIDR", SoftWhitelist{}, "192.168.1.0", false},
		{"InvalidFormat", SoftWhitelist{}, "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.isValidNetwork(tt.network); got != tt.want {
				t.Errorf("isValidNetwork() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSoftWhitelist_Set(t *testing.T) {
	s := NewSoftWhitelist()
	s.Set("user1", "192.168.1.0/24")

	t.Run("SetValid", func(t *testing.T) {
		if got := s.Get("user1"); len(got) != 1 || got[0] != "192.168.1.0/24" {
			t.Errorf("Expected network to be added, got %v", got)
		}
	})

	s.Set("user1", "10.0.0.0/8")
	t.Run("SetAdditionalNetwork", func(t *testing.T) {
		if got := s.Get("user1"); len(got) != 2 || got[1] != "10.0.0.0/8" {
			t.Errorf("Expected additional network to be added, got %v", got)
		}
	})

	s.Set("", "10.0.0.0/8")
	t.Run("SetEmptyUsername", func(t *testing.T) {
		if got := s.Get(""); got != nil {
			t.Errorf("Expected no networks for empty username, got %v", got)
		}
	})

	s.Set("user2", "invalid")
	t.Run("SetInvalidNetwork", func(t *testing.T) {
		if got := s.Get("user2"); got != nil {
			t.Errorf("Expected no networks for invalid network, got %v", got)
		}
	})
}

func TestSoftWhitelist_Get(t *testing.T) {
	s := NewSoftWhitelist()
	s.Set("user1", "192.168.1.0/24")

	tests := []struct {
		name     string
		s        SoftWhitelist
		username string
		want     []string
	}{
		{"GetExistingUser", s, "user1", []string{"192.168.1.0/24"}},
		{"GetNonExistingUser", s, "user2", nil},
		{"GetFromNilWhitelist", nil, "user1", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.Get(tt.username); !equalSlices(got, tt.want) {
				t.Errorf("Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewSoftAllow(t *testing.T) {
	t.Run("NewSoftWhitelist", func(t *testing.T) {
		if got := NewSoftWhitelist(); got == nil || len(got) != 0 {
			t.Errorf("NewSoftWhitelist() = %v, want empty SoftWhitelist", got)
		}
	})
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func TestSoftWhitelist_Delete(t *testing.T) {
	tests := []struct {
		name     string
		s        SoftWhitelist
		username string
		network  string
		want     map[string][]string
	}{
		{"DeleteFromNilWhitelist", nil, "user1", "192.168.1.0/24", nil},
		{"DeleteFromEmptyWhitelist", NewSoftWhitelist(), "user1", "192.168.1.0/24", map[string][]string{}},
		{"DeleteNonExistentNetwork", SoftWhitelist{"user1": {"192.168.1.0/24"}}, "user1", "10.0.0.0/8", SoftWhitelist{"user1": {"192.168.1.0/24"}}},
		{"DeleteExistingNetwork", SoftWhitelist{"user1": {"192.168.1.0/24", "10.0.0.0/8"}}, "user1", "192.168.1.0/24", SoftWhitelist{"user1": {"10.0.0.0/8"}}},
		{"DeleteOnlyNetwork", SoftWhitelist{"user1": {"192.168.1.0/24"}}, "user1", "192.168.1.0/24", map[string][]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.s.Delete(tt.username, tt.network)
			if !equalMaps(tt.s, tt.want) {
				t.Errorf("Delete() result = %v, want %v", tt.s, tt.want)
			}
		})
	}
}

func equalMaps(a, b SoftWhitelist) bool {
	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for k, v := range a {
		bv, ok := b[k]
		if !ok || !equalSlices(v, bv) {
			return false
		}
	}

	return true
}
