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

package compiler

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/spf13/viper"
)

const (
	testStringSetName      = "eu_countries"
	testStringSetReference = "@string." + testStringSetName
)

func TestCompilerAcceptsStringSetMembershipReferences(t *testing.T) {
	cfg := decodeStringSetPolicyConfig(t, map[string]any{
		testStringSetName: []any{"AT", "DE"},
	}, []any{
		stringSetPolicyFixture("allow_eu", "in", testStringSetReference),
		stringSetPolicyFixture("deny_non_eu", "not_in", testStringSetReference),
	})

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	policies := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth].Policies
	if len(policies) != 2 {
		t.Fatalf("compiled policies = %d, want 2", len(policies))
	}

	want := []string{"AT", "DE"}
	for _, compiled := range policies {
		if !reflect.DeepEqual(compiled.Root.Expected.Value, want) {
			t.Fatalf("policy %q operand = %#v, want %#v", compiled.Name, compiled.Root.Expected.Value, want)
		}
	}
}

func TestCompilerPreservesInlineStringMembershipLists(t *testing.T) {
	cfg := decodeStringSetPolicyConfig(t, map[string]any{
		testStringSetName: []any{"AT", "DE"},
	}, []any{
		stringSetPolicyFixture("allow_protocols", "in", []any{"imap", "smtp"}),
	})

	snapshot, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	compiled := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth].Policies[0]

	want := []any{"imap", "smtp"}
	if !reflect.DeepEqual(compiled.Root.Expected.Value, want) {
		t.Fatalf("inline operand = %#v, want %#v", compiled.Root.Expected.Value, want)
	}
}

func TestCompilerRejectsInvalidStringSets(t *testing.T) {
	for _, testCase := range invalidStringSetCases() {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := decodeStringSetPolicyConfig(t, testCase.sets, []any{
				stringSetPolicyFixtureWithAttribute("string_set_policy", testCase.attribute, "not_in", testCase.operand),
			})

			_, err := NewCompiler().Compile(context.Background(), Input{Config: cfg, Generation: 1})
			if err == nil {
				t.Fatal("Compile() error = nil, want invalid string set error")
			}

			for _, wantError := range testCase.wantErrors {
				if !strings.Contains(err.Error(), wantError) {
					t.Fatalf("Compile() error = %q, want %q", err, wantError)
				}
			}
		})
	}
}

type invalidStringSetCase struct {
	sets       map[string]any
	name       string
	attribute  string
	operand    string
	wantErrors []string
}

// invalidStringSetCases returns the table of rejected definition and reference shapes.
func invalidStringSetCases() []invalidStringSetCase {
	return []invalidStringSetCase{
		{
			name:       "unknown reference",
			sets:       map[string]any{testStringSetName: []any{"DE"}},
			attribute:  "request.protocol",
			operand:    "@string.unknown",
			wantErrors: []string{"auth.policy.policies[0].if.not_in", "unknown string set"},
		},
		{
			name:       "malformed reference",
			sets:       map[string]any{testStringSetName: []any{"DE"}},
			attribute:  "request.protocol",
			operand:    "@strings.eu_countries",
			wantErrors: []string{"auth.policy.policies[0].if.not_in", "string set reference"},
		},
		{
			name:       "invalid name",
			sets:       map[string]any{"EU-Countries": []any{"DE"}},
			attribute:  "request.protocol",
			operand:    "@string.EU-Countries",
			wantErrors: []string{"auth.policy.sets.strings.eu-countries", "lowercase letters"},
		},
		{
			name:       "empty set",
			sets:       map[string]any{testStringSetName: []any{}},
			attribute:  "request.protocol",
			operand:    testStringSetReference,
			wantErrors: []string{"auth.policy.sets.strings.eu_countries", "must not be empty"},
		},
		{
			name:       "empty entry",
			sets:       map[string]any{testStringSetName: []any{"DE", ""}},
			attribute:  "request.protocol",
			operand:    testStringSetReference,
			wantErrors: []string{"auth.policy.sets.strings.eu_countries[1]", "must not be empty"},
		},
		{
			name:       "duplicate entry",
			sets:       map[string]any{testStringSetName: []any{"DE", "DE"}},
			attribute:  "request.protocol",
			operand:    testStringSetReference,
			wantErrors: []string{"auth.policy.sets.strings.eu_countries[1]", "duplicates"},
		},
		{
			name:       "incompatible attribute",
			sets:       map[string]any{testStringSetName: []any{"DE"}},
			attribute:  "request.time.now",
			operand:    testStringSetReference,
			wantErrors: []string{"auth.policy.policies[0].if.not_in", "requires a string attribute"},
		},
	}
}

// decodeStringSetPolicyConfig decodes the public config shape used by string-set compiler tests.
func decodeStringSetPolicyConfig(t *testing.T, sets map[string]any, policies []any) config.File {
	t.Helper()

	decoder := viper.New()
	decoder.Set("auth.policy", map[string]any{
		"mode":           "enforce",
		"default_policy": policy.BuiltinDefaultSet,
		"sets": map[string]any{
			"strings": sets,
		},
		"policies": policies,
	})

	cfg := &config.FileSettings{}
	if err := decoder.Unmarshal(cfg); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	return cfg
}

// stringSetPolicyFixture builds one request-protocol policy with a referenced membership operand.
func stringSetPolicyFixture(name string, operator string, operand any) map[string]any {
	return stringSetPolicyFixtureWithAttribute(name, "request.protocol", operator, operand)
}

// stringSetPolicyFixtureWithAttribute builds one policy fixture for the selected scalar attribute.
func stringSetPolicyFixtureWithAttribute(name string, attribute string, operator string, operand any) map[string]any {
	return map[string]any{
		"name":       name,
		"stage":      string(policy.StagePreAuth),
		"operations": []any{string(policy.OperationAuthenticate)},
		"if": map[string]any{
			"attribute": attribute,
			operator:    operand,
		},
		"then": map[string]any{
			"decision":        string(policy.DecisionDeny),
			"response_marker": policy.ResponseMarkerFail,
		},
	}
}
