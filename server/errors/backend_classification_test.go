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

package errors

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// TestIsBackendTechnicalFailure pins both directions of the classification,
// because each mistake has its own security consequence: a technical fault
// counted as a wrong password bans legitimate addresses, and a wrong password
// treated as technical hides an attack from brute-force accounting.
func TestIsBackendTechnicalFailure(t *testing.T) {
	technical := map[string]error{
		"ldap pool exhausted":  ErrLDAPPoolExhausted,
		"backend temporary":    ErrBackendTemporaryFailure,
		"ldap search timeout":  ErrLDAPSearchTimeout,
		"ldap bind timeout":    ErrLDAPBindTimeout,
		"lua script execution": ErrBackendLua,
		"lua configuration":    ErrLuaConfig,
		"context deadline":     context.DeadlineExceeded,
		"context canceled":     context.Canceled,
		"wrapped with detail":  ErrBackendTemporaryFailure.WithDetail("connection reset by peer"),
		"wrapped by a caller":  fmt.Errorf("remote authority unavailable: %w", ErrBackendTemporaryFailure),
		"wrapped twice":        fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", ErrLDAPPoolExhausted)),
	}
	for name, err := range technical {
		if !IsBackendTechnicalFailure(err) {
			t.Errorf("%s must be technical", name)
		}
	}

	decisions := map[string]error{
		"nil":                 nil,
		"no passdb result":    ErrNoPassDBResult,
		"wrong lua user data": ErrBackendLuaWrongUserData,
		"unrelated error":     errors.New("credentials rejected"),
	}
	for name, err := range decisions {
		if IsBackendTechnicalFailure(err) {
			t.Errorf("%s must not be technical", name)
		}
	}
}
