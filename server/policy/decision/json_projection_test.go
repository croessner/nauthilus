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

package decision_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

func TestValueAccessorsSupportDeterministicJSONProjection(t *testing.T) {
	timestamp := time.Date(2026, time.August, 12, 9, 15, 0, 0, time.FixedZone("CEST", 2*60*60))
	values := map[string]decision.Value{
		"z_bytes": mustValue(t, decision.ValueInput{Bytes: []byte{0, 1, 2}}),
		"a_time":  mustValue(t, decision.ValueInput{Timestamp: &timestamp}),
		"m_list":  mustValue(t, decision.ValueInput{Strings: []string{"a", "b"}}),
	}

	projection := make(map[string]map[string]any, len(values))
	for name, value := range values {
		member, projected := projectValue(value)
		projection[name] = map[string]any{member: projected}
	}

	payload, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	want := `{"a_time":{"timestamp":"2026-08-12T07:15:00Z"},"m_list":{"strings":["a","b"]},"z_bytes":{"bytes":"AAEC"}}`
	if string(payload) != want {
		t.Fatalf("JSON projection = %s, want %s", payload, want)
	}
}

// projectValue models the deterministic later transport conversion contract.
func projectValue(value decision.Value) (string, any) {
	switch value.Kind() {
	case decision.ValueKindString:
		result, _ := value.StringValue()

		return "string", result
	case decision.ValueKindBoolean:
		result, _ := value.Boolean()

		return "boolean", result
	case decision.ValueKindInteger:
		result, _ := value.Integer()

		return "integer", result
	case decision.ValueKindDouble:
		result, _ := value.Double()

		return "double", result
	case decision.ValueKindStrings:
		result, _ := value.Strings()

		return "strings", result
	case decision.ValueKindBytes:
		result, _ := value.Bytes()

		return "bytes", base64.StdEncoding.EncodeToString(result)
	case decision.ValueKindTimestamp:
		result, _ := value.Timestamp()

		return "timestamp", result.Format(time.RFC3339Nano)
	default:
		panic(fmt.Sprintf("unexpected value kind %q", value.Kind()))
	}
}

// mustValue creates one strict value for projection tests.
func mustValue(t *testing.T, input decision.ValueInput) decision.Value {
	t.Helper()

	value, err := decision.NewValue(input)
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return value
}
