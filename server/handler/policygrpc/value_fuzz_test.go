// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policygrpc

import (
	"testing"

	policyv1 "github.com/croessner/nauthilus/v3/api/policy/v1"

	"google.golang.org/protobuf/proto"
)

func FuzzPolicyGRPCValueConversion(f *testing.F) {
	f.Add(mustPolicyValueSeed(f, &policyv1.Value{Kind: &policyv1.Value_String_{String_: "value"}}))
	f.Add(mustPolicyValueSeed(f, &policyv1.Value{Kind: &policyv1.Value_Strings{
		Strings: &policyv1.StringList{Values: []string{}},
	}}))
	f.Add([]byte{0xff, 0x00, 0x7f})

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64*1024 {
			t.Skip()
		}

		dto := &policyv1.Value{}
		if err := proto.Unmarshal(input, dto); err != nil {
			return
		}

		value, err := valueInput(dto)
		if err == nil && !value.Kind().IsValid() {
			t.Fatalf("successful conversion produced invalid kind %q", value.Kind())
		}
	})
}

// mustPolicyValueSeed encodes one deterministic protobuf fuzz seed.
func mustPolicyValueSeed(f *testing.F, value *policyv1.Value) []byte {
	f.Helper()

	encoded, err := proto.Marshal(value)
	if err != nil {
		f.Fatalf("proto.Marshal() error = %v", err)
	}

	return encoded
}
