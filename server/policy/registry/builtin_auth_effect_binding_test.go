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

package registry

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
)

const (
	retiredLuaActionEffect     = "authn/" + "lua_action_dispatch"
	retiredLuaPostActionEffect = "authn/" + "lua_post_action_enqueue"
)

func TestBuiltinStandardAuthPolicySetOwnsExecutableRules(t *testing.T) {
	contribution, err := NewBuiltinTargetContributor().Contribute(context.Background())
	if err != nil {
		t.Fatalf("Contribute() error = %v", err)
	}

	var standard PolicySetDefinition

	for _, policySet := range contribution.PolicySets() {
		if policySet.ID().String() == BuiltinStandardAuthPolicySet {
			standard = policySet

			break
		}
	}

	rules := standard.Rules()
	if len(rules) == 0 {
		t.Fatal("authn/standard_auth has no catalog-owned executable rules")
	}

	want := map[string]struct{}{
		"standard_brute_force_deny":        {},
		"standard_auth_success":            {},
		"standard_lookup_identity_success": {},
		"standard_list_accounts_success":   {},
		"standard_default_deny":            {},
	}
	for _, rule := range rules {
		delete(want, rule.Name())

		for _, effect := range rule.Effects() {
			if effect.ID() == retiredLuaActionEffect || effect.ID() == retiredLuaPostActionEffect {
				t.Errorf("authn/standard_auth rule %q retains legacy Lua action effect %q", rule.Name(), effect.ID())
			}
		}
	}

	if len(want) != 0 {
		t.Fatalf("authn/standard_auth missing executable rules: %v", want)
	}
}

func TestBuiltinAuthEffectBindingsAreCanonicalAndDetached(t *testing.T) {
	want := []BuiltinAuthEffectBinding{
		{
			EffectID:  builtinBruteForceEffect,
			Provider:  builtinBruteForceProvider,
			Execution: ExecutionHostSync,
		},
	}

	bindings := BuiltinAuthEffectBindings()
	if !reflect.DeepEqual(bindings, want) {
		t.Fatalf("builtin auth effect bindings = %#v, want %#v", bindings, want)
	}

	bindings[0] = BuiltinAuthEffectBinding{}

	if got := BuiltinAuthEffectBindings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("mutated builtin auth effect bindings = %#v, want detached %#v", got, want)
	}

	for _, binding := range want {
		resolved, ok := BuiltinAuthEffectBindingForEffect(binding.EffectID)
		if !ok || resolved != binding {
			t.Fatalf("binding for %q = %#v/%t, want %#v/true", binding.EffectID, resolved, ok, binding)
		}
	}

	for _, retired := range []string{retiredLuaActionEffect, retiredLuaPostActionEffect} {
		if binding, ok := BuiltinAuthEffectBindingForEffect(retired); ok {
			t.Errorf("retired builtin action effect %q still resolves to %#v", retired, binding)
		}
	}
}

func TestLegacyEffectSelectionSourceIsAbsent(t *testing.T) {
	for path, forbidden := range map[string][]string{
		"effect_catalog.go": {
			"selection" + "ID",
			"Selection" + "ID",
			"newEffectDefinitionWith" + "Selection",
		},
		"builtin_target_catalog.go": {
			"Selection" + " string",
			"BuiltinAuthEffect" + "SelectionIDs",
			"builtinTargetsForEffect" + "Selection",
		},
		"../runtime/target_catalog.go": {
			"effect" + "Selections",
			"LookupEffect" + "Selection",
			"claimEffect" + "Selections",
		},
		"../configinput/namespace.go": {
			"ObligationLuaAction" + "Dispatch",
			"ObligationLuaPostAction" + "Enqueue",
			".Selec" + "tion",
		},
		"../types.go": {"auth." + "obligation."},
	} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}

		for _, token := range forbidden {
			if strings.Contains(string(contents), token) {
				t.Errorf("production source %s retains legacy effect selection %q", path, token)
			}
		}
	}
}
