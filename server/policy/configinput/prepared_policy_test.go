// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
)

// TestPreparedPolicyOwnsOneNormalizedCompilableCandidate proves the production policy payload is self-contained.
func TestPreparedPolicyOwnsOneNormalizedCompilableCandidate(t *testing.T) {
	prepared, err := PreparePolicy(t.Context(), 17, policyconfig.PolicyConfig{})
	if err != nil {
		t.Fatalf("PreparePolicy() error = %v", err)
	}

	if prepared.GenerationID() != 17 || prepared.ValidatePolicyModel() != nil {
		t.Fatalf("prepared policy identity/validation = %d/%v", prepared.GenerationID(), prepared.ValidatePolicyModel())
	}

	clone, ok := prepared.ClonePolicyModel().(*PreparedPolicy)
	if !ok || clone == prepared || clone.GenerationID() != prepared.GenerationID() {
		t.Fatalf("ClonePolicyModel() = %T/%p, want detached PreparedPolicy", clone, clone)
	}

	catalog, definitions, err := prepared.Compile(t.Context(), &nativeGenerationAcceptor{})
	if err != nil {
		t.Fatalf("PreparedPolicy.Compile() error = %v", err)
	}

	if catalog == nil || len(definitions) == 0 {
		t.Fatalf("compiled catalog/definitions = %v/%d, want complete builtin material", catalog, len(definitions))
	}
}
