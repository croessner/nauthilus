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
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy"
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
	}

	if len(want) != 0 {
		t.Fatalf("authn/standard_auth missing executable rules: %v", want)
	}
}

func TestBuiltinAuthEffectBindingsAreExactAndDetached(t *testing.T) {
	want := []BuiltinAuthEffectBinding{
		{
			Selection: policy.ObligationBruteForceUpdate,
			EffectID:  builtinBruteForceEffect,
			Provider:  builtinBruteForceProvider,
			Execution: ExecutionHostSync,
		},
		{
			Selection: policy.ObligationLuaActionDispatch,
			EffectID:  builtinLuaActionEffect,
			Provider:  builtinLuaActionProvider,
			Execution: ExecutionHostSync,
		},
		{
			Selection: policy.ObligationLuaPostActionEnqueue,
			EffectID:  builtinPostActionEffect,
			Provider:  builtinPostActionProvider,
			Execution: ExecutionHostPostAction,
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
}
