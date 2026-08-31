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

package policyprovider_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/policyprovider"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

func TestPolicyProviderContractsRemainValueOnlyAndContextFirst(t *testing.T) {
	if policyprovider.PolicyFactsCollectCallback != "policy.facts.collect" {
		t.Fatalf("PolicyFactsCollectCallback = %q", policyprovider.PolicyFactsCollectCallback)
	}

	assertInterfaceMethods(t, reflect.TypeOf((*policyprovider.FactCollector)(nil)).Elem(), []string{"Collect", "Descriptor"}, "Collect")
	assertInterfaceMethods(t, reflect.TypeOf((*policyprovider.EffectExecutor)(nil)).Elem(), []string{"Descriptor", "Execute"}, "Execute")

	if reflect.TypeOf(policyprovider.FactRequest{}) == reflect.TypeOf(lualib.CommonRequest{}) {
		t.Fatal("FactRequest must not alias the auth-shaped CommonRequest")
	}

	types := []reflect.Type{
		reflect.TypeOf(policyprovider.TargetSelector{}),
		reflect.TypeOf(policyprovider.CallerView{}),
		reflect.TypeOf(policyprovider.FactView{}),
		reflect.TypeOf(policyprovider.FactRequest{}),
		reflect.TypeOf(policyprovider.FactOutputDescriptor{}),
		reflect.TypeOf(policyprovider.FactProviderDescriptor{}),
		reflect.TypeOf(policyprovider.FactValue{}),
		reflect.TypeOf(policyprovider.FactResult{}),
		reflect.TypeOf(policyprovider.ParameterDescriptor{}),
		reflect.TypeOf(policyprovider.EffectDescriptor{}),
		reflect.TypeOf(policyprovider.EffectProviderDescriptor{}),
		reflect.TypeOf(policyprovider.EffectParameter{}),
		reflect.TypeOf(policyprovider.EffectRequest{}),
		reflect.TypeOf(policyprovider.EffectResult{}),
	}

	for _, contractType := range types {
		assertNoAuthorityFields(t, contractType)
	}

	assertFields(t, reflect.TypeOf(policyprovider.FactResult{}), []string{"Facts", "ErrorClass"})
	assertFields(t, reflect.TypeOf(policyprovider.EffectResult{}), []string{"State", "ErrorClass"})
	assertFields(t, reflect.TypeOf(policyprovider.CallerView{}), []string{"Scopes", "Principal", "ClientID", "AuthenticationKind"})
}

func TestFactProviderDescriptorValidationIsStrictAndBounded(t *testing.T) {
	valid := validFactProviderDescriptor()
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	tests := map[string]func(*policyprovider.FactProviderDescriptor){
		"uppercase namespace": func(value *policyprovider.FactProviderDescriptor) { value.Namespace = "Mail" },
		"wildcard action":     func(value *policyprovider.FactProviderDescriptor) { value.Targets[0].Action = "*" },
		"normalized name":     func(value *policyprovider.FactProviderDescriptor) { value.Name = " reputation " },
		"duplicate target": func(value *policyprovider.FactProviderDescriptor) {
			value.Targets = append(value.Targets, value.Targets[0])
		},
		"duplicate output": func(value *policyprovider.FactProviderDescriptor) {
			value.Outputs = append(value.Outputs, value.Outputs[0])
		},
		"authority-shaped output": func(value *policyprovider.FactProviderDescriptor) { value.Outputs[0].Name = "lua.other.score" },
		"unbounded string":        func(value *policyprovider.FactProviderDescriptor) { value.Outputs[0].MaxLength = 0 },
		"zero timeout":            func(value *policyprovider.FactProviderDescriptor) { value.Timeout = 0 },
		"excessive timeout":       func(value *policyprovider.FactProviderDescriptor) { value.Timeout = 10*time.Minute + time.Nanosecond },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := validFactProviderDescriptor()
			mutate(&candidate)

			if err := candidate.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestEffectProviderDescriptorValidationIsStrictAndTyped(t *testing.T) {
	valid := validEffectProviderDescriptor()
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	tests := map[string]func(*policyprovider.EffectProviderDescriptor){
		"missing namespace": func(value *policyprovider.EffectProviderDescriptor) { value.Namespace = "" },
		"duplicate effect": func(value *policyprovider.EffectProviderDescriptor) {
			value.Effects = append(value.Effects, value.Effects[0])
		},
		"invalid execution": func(value *policyprovider.EffectProviderDescriptor) { value.Effects[0].Execution = "return_only" },
		"duplicate target": func(value *policyprovider.EffectProviderDescriptor) {
			value.Effects[0].Targets = append(value.Effects[0].Targets, value.Effects[0].Targets[0])
		},
		"duplicate parameter": func(value *policyprovider.EffectProviderDescriptor) {
			value.Effects[0].Parameters = append(value.Effects[0].Parameters, value.Effects[0].Parameters[0])
		},
		"invalid parameter bounds": func(value *policyprovider.EffectProviderDescriptor) { value.Effects[0].Parameters[0].MaxLength = 0 },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := validEffectProviderDescriptor()
			mutate(&candidate)

			if err := candidate.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestFactProviderResultAllowsOnlyDeclaredLocalValues(t *testing.T) {
	descriptor := validFactProviderDescriptor()
	value := mustStringValue(t, "trusted")

	if err := descriptor.ValidateResult(policyprovider.FactResult{}); err != nil {
		t.Fatalf("ValidateResult(zero facts) error = %v", err)
	}

	if err := descriptor.ValidateResult(policyprovider.FactResult{ErrorClass: policyprovider.ErrorClassUnavailable}); err != nil {
		t.Fatalf("ValidateResult(error class) error = %v", err)
	}

	result := policyprovider.FactResult{Facts: []policyprovider.FactValue{{Name: "risk.score", Value: value}}}
	if err := descriptor.ValidateResult(result); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}

	for name, invalid := range map[string]policyprovider.FactResult{
		"undeclared": {Facts: []policyprovider.FactValue{{Name: "other", Value: value}}},
		"duplicate":  {Facts: []policyprovider.FactValue{{Name: "risk.score", Value: value}, {Name: "risk.score", Value: value}}},
		"wrong kind": {Facts: []policyprovider.FactValue{{Name: "risk.score", Value: mustBooleanValue(t, true)}}},
		"facts and error class": {
			Facts:      []policyprovider.FactValue{{Name: "risk.score", Value: value}},
			ErrorClass: policyprovider.ErrorClassUnavailable,
		},
		"unknown error class": {ErrorClass: "temporary"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := descriptor.ValidateResult(invalid); err == nil {
				t.Fatal("ValidateResult() error = nil")
			}
		})
	}
}

func TestEffectResultHasClosedFailureState(t *testing.T) {
	valid := []policyprovider.EffectResult{
		{State: policyprovider.EffectStateSucceeded},
		{State: policyprovider.EffectStateFailed, ErrorClass: policyprovider.ErrorClassUnavailable},
		{State: policyprovider.EffectStateOutcomeUnknown, ErrorClass: policyprovider.ErrorClassTimeout},
	}

	for _, result := range valid {
		if err := result.Validate(); err != nil {
			t.Fatalf("Validate(%q) error = %v", result.State, err)
		}
	}

	for _, result := range []policyprovider.EffectResult{
		{},
		{State: "retry"},
		{State: policyprovider.EffectStateSucceeded, ErrorClass: policyprovider.ErrorClassInternal},
		{State: policyprovider.EffectStateFailed},
	} {
		if err := result.Validate(); err == nil {
			t.Fatalf("Validate(%q) error = nil", result.State)
		}
	}
}

func TestProviderDescriptorDefinitionBoundsMatchInternalContract(t *testing.T) {
	descriptor := validFactProviderDescriptor()
	descriptor.Targets = make([]policyprovider.TargetSelector, 256)
	descriptor.Outputs = make([]policyprovider.FactOutputDescriptor, 256)

	for index := range 256 {
		descriptor.Targets[index] = policyprovider.TargetSelector{Namespace: "authn", Action: fmt.Sprintf("action-%d", index)}
		descriptor.Outputs[index] = policyprovider.FactOutputDescriptor{
			Name:      fmt.Sprintf("risk.value_%d", index),
			Category:  decision.FactCategoryEnvironment,
			Kind:      decision.ValueKindString,
			MaxLength: 64,
		}
	}

	if err := descriptor.Validate(); err != nil {
		t.Fatalf("Validate(256 definitions) error = %v", err)
	}

	descriptor.Targets = append(descriptor.Targets, policyprovider.TargetSelector{Namespace: "authn", Action: "overflow"})
	if err := descriptor.Validate(); err == nil {
		t.Fatal("Validate(257 targets) error = nil")
	}

	descriptor = validFactProviderDescriptor()

	descriptor.Outputs = make([]policyprovider.FactOutputDescriptor, 257)
	for index := range descriptor.Outputs {
		descriptor.Outputs[index] = policyprovider.FactOutputDescriptor{
			Name:      fmt.Sprintf("risk.value_%d", index),
			Category:  decision.FactCategoryEnvironment,
			Kind:      decision.ValueKindString,
			MaxLength: 64,
		}
	}

	if err := descriptor.Validate(); err == nil {
		t.Fatal("Validate(257 outputs) error = nil")
	}
}

func TestEffectParameterBoundsMatchInternalContract(t *testing.T) {
	effectDescriptor := validEffectProviderDescriptor()

	effectDescriptor.Effects[0].Parameters = make([]policyprovider.ParameterDescriptor, 64)
	for index := range effectDescriptor.Effects[0].Parameters {
		effectDescriptor.Effects[0].Parameters[index] = policyprovider.ParameterDescriptor{
			Name:      fmt.Sprintf("parameter_%d", index),
			Kind:      decision.ValueKindString,
			MaxLength: 64,
		}
	}

	if err := effectDescriptor.Validate(); err != nil {
		t.Fatalf("Validate(64 parameters) error = %v", err)
	}

	effectDescriptor.Effects[0].Parameters = append(
		effectDescriptor.Effects[0].Parameters,
		policyprovider.ParameterDescriptor{Name: "overflow", Kind: decision.ValueKindString, MaxLength: 64},
	)
	if err := effectDescriptor.Validate(); err == nil {
		t.Fatal("Validate(65 parameters) error = nil")
	}
}

// validFactProviderDescriptor returns one reusable valid fact capability.
func validFactProviderDescriptor() policyprovider.FactProviderDescriptor {
	return policyprovider.FactProviderDescriptor{
		Namespace: "mail",
		Name:      "reputation",
		Targets:   []policyprovider.TargetSelector{{Namespace: "authn", Action: "authenticate"}},
		Outputs: []policyprovider.FactOutputDescriptor{{
			Name:      "risk.score",
			Category:  decision.FactCategoryEnvironment,
			Kind:      decision.ValueKindString,
			MaxLength: 64,
		}},
		Timeout: 250 * time.Millisecond,
	}
}

// validEffectProviderDescriptor returns one reusable valid effect capability.
func validEffectProviderDescriptor() policyprovider.EffectProviderDescriptor {
	return policyprovider.EffectProviderDescriptor{
		Namespace: "mail",
		Name:      "audit",
		Effects: []policyprovider.EffectDescriptor{{
			Name:      "record-audit",
			Targets:   []policyprovider.TargetSelector{{Namespace: "authn", Action: "authenticate"}},
			Execution: policyprovider.EffectExecutionHostPostAction,
			Parameters: []policyprovider.ParameterDescriptor{{
				Name:           "message",
				Kind:           decision.ValueKindString,
				MaxLength:      128,
				Required:       true,
				NonEmpty:       true,
				AllowedStrings: []string{"accepted", "rejected"},
			}},
		}},
	}
}

// mustStringValue constructs one strict string test value.
func mustStringValue(t *testing.T, input string) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return value
}

// mustBooleanValue constructs one strict boolean test value.
func mustBooleanValue(t *testing.T, input bool) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{Boolean: &input})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return value
}

// assertInterfaceMethods freezes one narrow callback method set and its context position.
func assertInterfaceMethods(t *testing.T, interfaceType reflect.Type, want []string, contextMethod string) {
	t.Helper()

	if interfaceType.NumMethod() != len(want) {
		t.Fatalf("%s method count = %d, want %d", interfaceType, interfaceType.NumMethod(), len(want))
	}

	for index, name := range want {
		method := interfaceType.Method(index)
		if method.Name != name {
			t.Fatalf("%s method %d = %s, want %s", interfaceType, index, method.Name, name)
		}
	}

	method, ok := interfaceType.MethodByName(contextMethod)
	if !ok || method.Type.NumIn() == 0 || method.Type.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		t.Fatalf("%s.%s must accept context.Context first", interfaceType, contextMethod)
	}
}

// assertNoAuthorityFields rejects public controls outside the value-only callback boundary.
func assertNoAuthorityFields(t *testing.T, contractType reflect.Type) {
	t.Helper()

	for index := range contractType.NumField() {
		field := contractType.Field(index)
		name := strings.ToLower(field.Name)

		for _, forbidden := range []string{
			"decision", "abort", "planorder", "priority", "activation", "trustedfact",
			"provenance", "authority", "response", "mutation", "schedule", "checkpoint",
			"retry", "replay", "idempot", "dedup", "enqueue", "detach", "worker", "gate", "host",
		} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("%s exposes forbidden field %s", contractType, field.Name)
			}
		}
	}
}

// assertFields freezes the complete exported shape of one narrow value type.
func assertFields(t *testing.T, contractType reflect.Type, want []string) {
	t.Helper()

	if contractType.NumField() != len(want) {
		t.Fatalf("%s field count = %d, want %d", contractType, contractType.NumField(), len(want))
	}

	for index, name := range want {
		if got := contractType.Field(index).Name; got != name {
			t.Fatalf("%s field %d = %s, want %s", contractType, index, got, name)
		}
	}
}
