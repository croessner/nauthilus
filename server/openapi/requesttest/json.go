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

package requesttest

import (
	"encoding/json"
	"reflect"
	"testing"
)

// RoundTripJSON marshals source and unmarshals it into target for adapter
// tests that verify two DTOs share the same JSON boundary.
func RoundTripJSON(t testing.TB, source any, target any) {
	t.Helper()

	body, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("marshal JSON boundary source: %v", err)
	}

	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("unmarshal JSON boundary target: %v", err)
	}
}

// RequireStringPointer verifies an optional generated string field.
func RequireStringPointer(t testing.TB, name string, got *string, want string) {
	t.Helper()

	if got == nil {
		t.Fatalf("%s missing, want %q", name, want)

		return
	}

	if *got != want {
		t.Fatalf("%s = %q, want %q", name, *got, want)
	}
}

// RequireStringSlicePointer verifies an optional generated string slice field.
func RequireStringSlicePointer(t testing.TB, name string, got *[]string, want []string) {
	t.Helper()

	if got == nil {
		t.Fatalf("%s missing, want %v", name, want)

		return
	}

	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("%s = %v, want %v", name, *got, want)
	}
}
