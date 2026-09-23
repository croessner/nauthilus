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

// TestTokenValidationUnavailableKeepsCause pins that the classification never
// hides the technical cause, because transports map a canceled request context
// differently from an unreachable token store.
func TestTokenValidationUnavailableKeepsCause(t *testing.T) {
	err := NewTokenValidationUnavailable(fmt.Errorf("redis get: %w", context.Canceled))

	if !IsTokenValidationUnavailable(err) {
		t.Fatal("marked error must be classified as unavailable")
	}

	if !errors.Is(err, context.Canceled) {
		t.Fatal("marked error must keep its technical cause")
	}

	wrapped := fmt.Errorf("validate token: %w", err)
	if !IsTokenValidationUnavailable(wrapped) {
		t.Fatal("classification must survive wrapping")
	}

	if NewTokenValidationUnavailable(wrapped) != wrapped {
		t.Fatal("marking an already marked error must be idempotent")
	}
}

// TestTokenValidationUnavailableRejectsVerdicts pins that ordinary token
// rejections are never read as a technical failure.
func TestTokenValidationUnavailableRejectsVerdicts(t *testing.T) {
	for name, err := range map[string]error{
		"nil":            nil,
		"invalid token":  errors.New("invalid token"),
		"context cancel": context.Canceled,
	} {
		if IsTokenValidationUnavailable(err) {
			t.Errorf("%s must not be classified as unavailable", name)
		}
	}

	if NewTokenValidationUnavailable(nil) != nil {
		t.Fatal("a nil cause must stay nil")
	}
}
