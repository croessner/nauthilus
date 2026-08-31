// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyhttp

import (
	"encoding/json"
	"testing"

	"github.com/croessner/nauthilus/v3/server/openapi/generated/management"
)

func FuzzPolicyHTTPValueConversion(f *testing.F) {
	f.Add([]byte(`{"string":"value"}`))
	f.Add([]byte(`{"strings":[]}`))
	f.Add([]byte(`{"records":[{"fields":[{"name":"state","value":{"strings":[]}}]}]}`))
	f.Add([]byte(`{"string":"value","boolean":true}`))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64*1024 {
			t.Skip()
		}

		var dto management.PolicyValue
		if err := json.Unmarshal(input, &dto); err != nil {
			return
		}

		value, err := valueInput(dto)
		if err == nil && !value.Kind().IsValid() {
			t.Fatalf("successful conversion produced invalid kind %q", value.Kind())
		}
	})
}
