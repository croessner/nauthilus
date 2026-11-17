// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package runtime

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// TestFoldedTerminalObligationsKeepTheirParameters rejects a rule obligation that would be folded into the terminal
// completion with parameters other than the terminal declaration, and keeps identical or unrelated obligations.
func TestFoldedTerminalObligationsKeepTheirParameters(t *testing.T) {
	const effectID = "authn/lua_action_record"

	terminal := []registry.EffectUse{mustTerminalEffectUse(t, effectID, map[string]decision.Value{
		"channel": mustTerminalString(t, "audit"),
	})}

	for _, testCase := range []struct {
		name    string
		use     registry.EffectUse
		wantErr bool
	}{
		{name: "identical parameters", use: terminal[0]},
		{name: "unrelated effect", use: mustTerminalEffectUse(t, "authn/lua_action_other", nil)},
		{name: "different parameters", wantErr: true, use: mustTerminalEffectUse(t, effectID, map[string]decision.Value{
			"channel": mustTerminalString(t, "security"),
		})},
		{name: "missing parameters", wantErr: true, use: mustTerminalEffectUse(t, effectID, nil)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rules := []CompiledRule{{record: CompiledRuleRecord{Name: "rule", Effects: []registry.EffectUse{testCase.use}}}}

			err := validateFoldedTerminalObligations(rules, terminal)
			if testCase.wantErr != errors.Is(err, ErrInvalidCompiledTarget) {
				t.Fatalf("validateFoldedTerminalObligations() error = %v, want rejection %t", err, testCase.wantErr)
			}
		})
	}
}

// mustTerminalEffectUse constructs one validated effect selection.
func mustTerminalEffectUse(t *testing.T, id string, parameters map[string]decision.Value) registry.EffectUse {
	t.Helper()

	use, err := registry.NewEffectUse(id, parameters)
	if err != nil {
		t.Fatalf("NewEffectUse(%s) error = %v", id, err)
	}

	return use
}

// mustTerminalString constructs one strict string parameter value.
func mustTerminalString(t *testing.T, input string) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err != nil {
		t.Fatalf("NewValue(%q) error = %v", input, err)
	}

	return value
}
