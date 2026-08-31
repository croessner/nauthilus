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

package pluginapi

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDecisionProviderInterfacesKeepContextFirstAndRegistrarAdditive(t *testing.T) {
	assertDecisionProviderInterface(
		t,
		reflect.TypeFor[DecisionFactProvider](),
		"Collect",
		reflect.TypeFor[DecisionFactRequest](),
		reflect.TypeFor[DecisionFactProviderDescriptor](),
		reflect.TypeFor[DecisionFactResult](),
	)
	assertDecisionProviderInterface(
		t,
		reflect.TypeFor[DecisionEffectProvider](),
		"Execute",
		reflect.TypeFor[DecisionEffectRequest](),
		reflect.TypeFor[DecisionEffectProviderDescriptor](),
		reflect.TypeFor[DecisionEffectResult](),
	)
	assertLegacyRegistrarUnchanged(t)
	assertAdditiveDecisionRegistrar(t)
}

// assertDecisionProviderInterface freezes one narrow descriptor and invocation method set.
func assertDecisionProviderInterface(
	t *testing.T,
	interfaceType reflect.Type,
	methodName string,
	requestType reflect.Type,
	descriptorType reflect.Type,
	resultType reflect.Type,
) {
	t.Helper()

	if interfaceType.NumMethod() != 2 {
		t.Fatalf("%s method count = %d, want Descriptor plus %s only", interfaceType, interfaceType.NumMethod(), methodName)
	}

	assertDecisionDescriptorMethod(t, interfaceType, descriptorType)
	assertDecisionInvocationMethod(t, interfaceType, methodName, requestType, resultType)
}

// assertDecisionDescriptorMethod checks the exact value-only descriptor signature.
func assertDecisionDescriptorMethod(t *testing.T, interfaceType reflect.Type, descriptorType reflect.Type) {
	t.Helper()

	descriptor, exists := interfaceType.MethodByName("Descriptor")
	if !exists {
		t.Fatalf("%s must expose Descriptor", interfaceType)
	}

	if descriptor.Type.NumIn() != 0 || descriptor.Type.NumOut() != 1 || descriptor.Type.Out(0) != descriptorType {
		t.Fatalf("Descriptor signature = %s, want func() %s", descriptor.Type, descriptorType)
	}
}

// assertDecisionInvocationMethod checks context-first input and exact result types.
func assertDecisionInvocationMethod(
	t *testing.T,
	interfaceType reflect.Type,
	methodName string,
	requestType reflect.Type,
	resultType reflect.Type,
) {
	t.Helper()

	method, exists := interfaceType.MethodByName(methodName)
	if !exists {
		t.Fatalf("%s must expose %s", interfaceType, methodName)
	}

	if method.Type.NumIn() != 2 || method.Type.In(0) != reflect.TypeFor[context.Context]() || method.Type.In(1) != requestType {
		t.Fatalf("%s signature = %s, want context first and %s second", methodName, method.Type, requestType)
	}

	if method.Type.NumOut() != 2 || method.Type.Out(0) != resultType || method.Type.Out(1) != reflect.TypeFor[error]() {
		t.Fatalf("%s results = %s, want %s and error", methodName, method.Type, resultType)
	}
}

// assertLegacyRegistrarUnchanged proves generic registration did not widen the existing contract.
func assertLegacyRegistrarUnchanged(t *testing.T) {
	t.Helper()

	wantRegistrarMethods := []string{
		"Config",
		"RegisterBackend",
		"RegisterDebugModule",
		"RegisterEnvironmentSource",
		"RegisterHook",
		"RegisterInitTask",
		"RegisterObligationTarget",
		"RegisterPolicyAttribute",
		"RegisterPostActionTarget",
		"RegisterSubjectSource",
		"RequireCapability",
	}

	registrar := reflect.TypeFor[Registrar]()
	if registrar.NumMethod() != len(wantRegistrarMethods) {
		t.Fatalf("Registrar method count = %d, want %d; generic registration must remain optional", registrar.NumMethod(), len(wantRegistrarMethods))
	}

	for _, name := range wantRegistrarMethods {
		if _, exists := registrar.MethodByName(name); !exists {
			t.Fatalf("Registrar no longer exposes legacy method %s", name)
		}
	}
}

// assertAdditiveDecisionRegistrar freezes the separate two-method optional contract.
func assertAdditiveDecisionRegistrar(t *testing.T) {
	t.Helper()

	decisionRegistrar := reflect.TypeFor[DecisionRegistrar]()
	if decisionRegistrar.NumMethod() != 2 {
		t.Fatalf("DecisionRegistrar method count = %d, want the two additive registrations only", decisionRegistrar.NumMethod())
	}

	for _, name := range []string{"RegisterDecisionEffectProvider", "RegisterDecisionFactProvider"} {
		if _, exists := decisionRegistrar.MethodByName(name); !exists {
			t.Fatalf("DecisionRegistrar must expose %s", name)
		}
	}
}

func TestDecisionPublicResultFieldsFreezeAuthorityBoundary(t *testing.T) {
	assertExactExportedFields(t, reflect.TypeFor[DecisionTargetSelector](), []string{"Namespace", "Action"})
	assertExactExportedFields(t, reflect.TypeFor[DecisionFactOutputDescriptor](), []string{"Name", "Category", "Kind", "MaxLength", "MaxItems", "MaxBytes"})
	assertExactExportedFields(t, reflect.TypeFor[DecisionFactProviderDescriptor](), []string{"Targets", "Outputs", "Namespace", "Name", "Timeout"})
	assertExactExportedFields(t, reflect.TypeFor[DecisionEffectParameterDescriptor](), []string{"AllowedStrings", "Name", "Kind", "MaxLength", "MaxItems", "MaxBytes", "NonEmpty", "Required"})
	assertExactExportedFields(t, reflect.TypeFor[DecisionEffectDescriptor](), []string{"Targets", "Parameters", "Name", "Execution"})
	assertExactExportedFields(t, reflect.TypeFor[DecisionEffectProviderDescriptor](), []string{"Effects", "Namespace", "Name"})
	assertExactExportedFields(t, reflect.TypeFor[DecisionFactOutput](), []string{"Name", "Value"})
	assertExactExportedFields(t, reflect.TypeFor[DecisionFactResult](), []string{"Facts", "ErrorClass"})
	assertExactExportedFields(t, reflect.TypeFor[DecisionEffectResult](), []string{"Outcome", "ErrorClass"})

	for _, contractType := range []reflect.Type{
		reflect.TypeFor[DecisionFactProviderDescriptor](),
		reflect.TypeFor[DecisionFactOutputDescriptor](),
		reflect.TypeFor[DecisionFactResult](),
		reflect.TypeFor[DecisionEffectProviderDescriptor](),
		reflect.TypeFor[DecisionEffectDescriptor](),
		reflect.TypeFor[DecisionEffectResult](),
	} {
		assertNoForbiddenDecisionFields(t, contractType)
	}
}

func TestDecisionValueIsStrictAndDeeplyOwned(t *testing.T) {
	t.Run("strict one-of", testDecisionValueStrictOneOf)
	t.Run("owned strings", testDecisionValueOwnsStrings)
	t.Run("owned bytes", testDecisionValueOwnsBytes)
	t.Run("normalized timestamp", testDecisionValueNormalizesTimestamp)
}

// testDecisionValueStrictOneOf checks absent, ambiguous, non-finite, and invalid UTF-8 input.
func testDecisionValueStrictOneOf(t *testing.T) {
	text := "hello"
	boolean := true
	double := math.Inf(1)

	if _, err := NewDecisionValue(DecisionValueInput{}); !errors.Is(err, ErrInvalidDecisionContract) {
		t.Fatalf("NewDecisionValue(empty) error = %v, want ErrInvalidDecisionContract", err)
	}

	if _, err := NewDecisionValue(DecisionValueInput{String: &text, Boolean: &boolean}); !errors.Is(err, ErrInvalidDecisionContract) {
		t.Fatalf("NewDecisionValue(multiple) error = %v, want ErrInvalidDecisionContract", err)
	}

	if _, err := NewDecisionValue(DecisionValueInput{Double: &double}); !errors.Is(err, ErrInvalidDecisionContract) {
		t.Fatalf("NewDecisionValue(non-finite) error = %v, want ErrInvalidDecisionContract", err)
	}

	invalidUTF8 := string([]byte{0xff})
	if _, err := NewDecisionValue(DecisionValueInput{String: &invalidUTF8}); !errors.Is(err, ErrInvalidDecisionContract) {
		t.Fatalf("NewDecisionValue(invalid UTF-8) error = %v, want ErrInvalidDecisionContract", err)
	}
}

// testDecisionValueOwnsStrings checks input and accessor copies for string lists.
func testDecisionValueOwnsStrings(t *testing.T) {
	stringsValue := []string{"one", "two"}

	list, err := NewDecisionValue(DecisionValueInput{Strings: stringsValue})
	if err != nil {
		t.Fatalf("NewDecisionValue(strings) error = %v", err)
	}

	stringsValue[0] = "changed"

	gotList, ok := list.Strings()
	if !ok || !reflect.DeepEqual(gotList, []string{"one", "two"}) {
		t.Fatalf("Strings() = %#v, %v, want owned original", gotList, ok)
	}

	gotList[0] = "again"
	gotList, _ = list.Strings()

	if gotList[0] != "one" {
		t.Fatal("Strings() exposed mutable storage")
	}
}

func TestDecisionValuePreservesPresentEmptyStrings(t *testing.T) {
	value, err := NewDecisionValue(DecisionValueInput{Strings: []string{}})
	if err != nil {
		t.Fatalf("NewDecisionValue(empty strings) error = %v", err)
	}

	stringsValue, ok := value.Strings()
	if !ok || stringsValue == nil || len(stringsValue) != 0 {
		t.Fatalf("Strings() = %#v, %t, want non-nil empty list", stringsValue, ok)
	}

	anyValue, ok := value.Any()

	anyStrings, typed := anyValue.([]string)
	if !ok || !typed || anyStrings == nil || len(anyStrings) != 0 {
		t.Fatalf("Any() = %#v, %t, want non-nil empty string list", anyValue, ok)
	}
}

// testDecisionValueOwnsBytes checks input and accessor copies for bytes.
func testDecisionValueOwnsBytes(t *testing.T) {
	bytesValue := []byte("secret-free")

	bytes, err := NewDecisionValue(DecisionValueInput{Bytes: bytesValue})
	if err != nil {
		t.Fatalf("NewDecisionValue(bytes) error = %v", err)
	}

	bytesValue[0] = 'X'

	gotBytes, ok := bytes.Bytes()
	if !ok || string(gotBytes) != "secret-free" {
		t.Fatalf("Bytes() = %q, %v, want owned original", gotBytes, ok)
	}
}

// testDecisionValueNormalizesTimestamp checks monotonic stripping and UTC normalization.
func testDecisionValueNormalizesTimestamp(t *testing.T) {
	timestamp := time.Date(2026, time.August, 25, 12, 0, 0, 123, time.FixedZone("fixture", 3600))

	instant, err := NewDecisionValue(DecisionValueInput{Timestamp: &timestamp})
	if err != nil {
		t.Fatalf("NewDecisionValue(timestamp) error = %v", err)
	}

	gotTime, ok := instant.Timestamp()
	if !ok || gotTime.Location() != time.UTC || !gotTime.Equal(timestamp) {
		t.Fatalf("Timestamp() = %v, %v, want UTC-normalized instant", gotTime, ok)
	}
}

func TestValidateDecisionFactProviderDescriptorIsStrict(t *testing.T) {
	valid := validDecisionFactProviderDescriptor(t)

	tests := []struct {
		name   string
		mutate func(*DecisionFactProviderDescriptor)
	}{
		{name: "namespace case", mutate: func(value *DecisionFactProviderDescriptor) { value.Namespace = "Mail.Security" }},
		{name: "namespace whitespace", mutate: func(value *DecisionFactProviderDescriptor) { value.Namespace = " mail.security" }},
		{name: "provider name", mutate: func(value *DecisionFactProviderDescriptor) { value.Name = "risk-provider" }},
		{name: "empty targets", mutate: func(value *DecisionFactProviderDescriptor) { value.Targets = nil }},
		{name: "invalid action", mutate: func(value *DecisionFactProviderDescriptor) { value.Targets[0].Action = "Evaluate" }},
		{name: "wildcard target", mutate: func(value *DecisionFactProviderDescriptor) { value.Targets[0].Namespace = "mail.*" }},
		{name: "duplicate target", mutate: func(value *DecisionFactProviderDescriptor) { value.Targets = append(value.Targets, value.Targets[0]) }},
		{name: "empty outputs", mutate: func(value *DecisionFactProviderDescriptor) { value.Outputs = nil }},
		{name: "invalid output name", mutate: func(value *DecisionFactProviderDescriptor) { value.Outputs[0].Name = "plugin.sample.score" }},
		{name: "duplicate output", mutate: func(value *DecisionFactProviderDescriptor) { value.Outputs = append(value.Outputs, value.Outputs[0]) }},
		{name: "invalid category", mutate: func(value *DecisionFactProviderDescriptor) { value.Outputs[0].Category = "caller" }},
		{name: "invalid kind", mutate: func(value *DecisionFactProviderDescriptor) { value.Outputs[0].Kind = "json" }},
		{name: "missing string bound", mutate: func(value *DecisionFactProviderDescriptor) { value.Outputs[0].MaxLength = 0 }},
		{name: "mixed string bound", mutate: func(value *DecisionFactProviderDescriptor) { value.Outputs[0].MaxBytes = 1 }},
		{name: "zero timeout", mutate: func(value *DecisionFactProviderDescriptor) { value.Timeout = 0 }},
		{name: "negative timeout", mutate: func(value *DecisionFactProviderDescriptor) { value.Timeout = -time.Second }},
		{name: "excessive timeout", mutate: func(value *DecisionFactProviderDescriptor) {
			value.Timeout = MaximumDecisionFactProviderTimeout + time.Nanosecond
		}},
	}

	if err := ValidateDecisionFactProviderDescriptor(valid); err != nil {
		t.Fatalf("ValidateDecisionFactProviderDescriptor(valid) error = %v", err)
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := cloneDecisionFactProviderDescriptor(valid)
			testCase.mutate(&candidate)

			if err := ValidateDecisionFactProviderDescriptor(candidate); !errors.Is(err, ErrInvalidDecisionContract) {
				t.Fatalf("ValidateDecisionFactProviderDescriptor() error = %v, want ErrInvalidDecisionContract", err)
			}
		})
	}
}

func TestDecisionLocalFactNameReservesNativeQualificationBudget(t *testing.T) {
	descriptor := validDecisionFactProviderDescriptor(t)
	descriptor.Outputs[0] = DecisionFactOutputDescriptor{
		Name:     strings.Repeat("x", 121),
		Category: DecisionFactCategoryEnvironment,
		Kind:     DecisionValueKindBoolean,
	}

	if err := ValidateDecisionFactProviderDescriptor(descriptor); err != nil {
		t.Fatalf("ValidateDecisionFactProviderDescriptor(121-byte local name) error = %v", err)
	}

	descriptor.Outputs[0].Name += "x"
	if err := ValidateDecisionFactProviderDescriptor(descriptor); !errors.Is(err, ErrInvalidDecisionContract) {
		t.Fatalf("ValidateDecisionFactProviderDescriptor(122-byte local name) error = %v, want ErrInvalidDecisionContract", err)
	}
}

func TestValidateDecisionEffectProviderDescriptorIsStrict(t *testing.T) {
	valid := validDecisionEffectProviderDescriptor()

	tests := []struct {
		name   string
		mutate func(*DecisionEffectProviderDescriptor)
	}{
		{name: "namespace", mutate: func(value *DecisionEffectProviderDescriptor) { value.Namespace = "mail-security" }},
		{name: "provider name", mutate: func(value *DecisionEffectProviderDescriptor) { value.Name = "Notifier" }},
		{name: "empty effects", mutate: func(value *DecisionEffectProviderDescriptor) { value.Effects = nil }},
		{name: "effect name", mutate: func(value *DecisionEffectProviderDescriptor) { value.Effects[0].Name = "notify.now" }},
		{name: "duplicate effect", mutate: func(value *DecisionEffectProviderDescriptor) { value.Effects = append(value.Effects, value.Effects[0]) }},
		{name: "wildcard target", mutate: func(value *DecisionEffectProviderDescriptor) { value.Effects[0].Targets[0].Namespace = "mail.*" }},
		{name: "duplicate target", mutate: func(value *DecisionEffectProviderDescriptor) {
			value.Effects[0].Targets = append(value.Effects[0].Targets, value.Effects[0].Targets[0])
		}},
		{name: "return only", mutate: func(value *DecisionEffectProviderDescriptor) { value.Effects[0].Execution = "return_only" }},
		{name: "unknown execution", mutate: func(value *DecisionEffectProviderDescriptor) { value.Effects[0].Execution = "worker" }},
		{name: "duplicate parameter", mutate: func(value *DecisionEffectProviderDescriptor) {
			value.Effects[0].Parameters = append(value.Effects[0].Parameters, value.Effects[0].Parameters[0])
		}},
		{name: "parameter name", mutate: func(value *DecisionEffectProviderDescriptor) {
			value.Effects[0].Parameters[0].Name = "recipient.address"
		}},
		{name: "parameter kind", mutate: func(value *DecisionEffectProviderDescriptor) { value.Effects[0].Parameters[0].Kind = "object" }},
		{name: "parameter bound", mutate: func(value *DecisionEffectProviderDescriptor) { value.Effects[0].Parameters[0].MaxLength = 0 }},
		{name: "enum duplicate", mutate: func(value *DecisionEffectProviderDescriptor) {
			value.Effects[0].Parameters[0].AllowedStrings = []string{"ops", "ops"}
		}},
		{name: "enum wrong kind", mutate: func(value *DecisionEffectProviderDescriptor) {
			value.Effects[0].Parameters[0] = DecisionEffectParameterDescriptor{Name: "urgent", Kind: DecisionValueKindBoolean, AllowedStrings: []string{"yes"}}
		}},
	}

	if err := ValidateDecisionEffectProviderDescriptor(valid); err != nil {
		t.Fatalf("ValidateDecisionEffectProviderDescriptor(valid) error = %v", err)
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := cloneDecisionEffectProviderDescriptor(valid)
			testCase.mutate(&candidate)

			if err := ValidateDecisionEffectProviderDescriptor(candidate); !errors.Is(err, ErrInvalidDecisionContract) {
				t.Fatalf("ValidateDecisionEffectProviderDescriptor() error = %v, want ErrInvalidDecisionContract", err)
			}
		})
	}
}

func TestValidateDecisionFactResultUsesDeclaredLocalOutputs(t *testing.T) {
	descriptor := validDecisionFactProviderDescriptor(t)
	value := mustDecisionStringValue(t, "high")
	valid := DecisionFactResult{Facts: []DecisionFactOutput{{Name: "risk.score", Value: value}}}

	if err := ValidateDecisionFactResult(descriptor, valid); err != nil {
		t.Fatalf("ValidateDecisionFactResult(valid) error = %v", err)
	}

	if err := ValidateDecisionFactResult(descriptor, DecisionFactResult{}); err != nil {
		t.Fatalf("ValidateDecisionFactResult(zero facts) error = %v", err)
	}

	tests := []DecisionFactResult{
		{Facts: []DecisionFactOutput{{Name: "plugin.sample.risk.score", Value: value}}},
		{Facts: []DecisionFactOutput{{Name: "undeclared", Value: value}}},
		{Facts: []DecisionFactOutput{{Name: "risk.score", Value: value}, {Name: "risk.score", Value: value}}},
		{Facts: []DecisionFactOutput{{Name: "risk.score", Value: mustDecisionBooleanValue(t, true)}}},
		{Facts: []DecisionFactOutput{{Name: "risk.score", Value: mustDecisionStringValue(t, strings.Repeat("x", 65))}}},
		{Facts: valid.Facts, ErrorClass: DecisionErrorClassInternal},
		{ErrorClass: "retryable"},
	}

	for index, result := range tests {
		if err := ValidateDecisionFactResult(descriptor, result); !errors.Is(err, ErrInvalidDecisionContract) {
			t.Fatalf("case %d error = %v, want ErrInvalidDecisionContract", index, err)
		}
	}

	if err := ValidateDecisionFactResult(descriptor, DecisionFactResult{ErrorClass: DecisionErrorClassUnavailable}); err != nil {
		t.Fatalf("ValidateDecisionFactResult(failure) error = %v", err)
	}
}

func TestValidateDecisionEffectResultFreezesOutcomeAndErrorClass(t *testing.T) {
	valid := []DecisionEffectResult{
		{Outcome: DecisionEffectOutcomeSucceeded},
		{Outcome: DecisionEffectOutcomeFailed, ErrorClass: DecisionErrorClassInvalidInput},
		{Outcome: DecisionEffectOutcomeUnknown, ErrorClass: DecisionErrorClassUnavailable},
	}

	for _, result := range valid {
		if err := ValidateDecisionEffectResult(result); err != nil {
			t.Fatalf("ValidateDecisionEffectResult(%#v) error = %v", result, err)
		}
	}

	invalid := []DecisionEffectResult{
		{},
		{Outcome: "queued"},
		{Outcome: DecisionEffectOutcomeSucceeded, ErrorClass: DecisionErrorClassInternal},
		{Outcome: DecisionEffectOutcomeFailed},
		{Outcome: DecisionEffectOutcomeUnknown, ErrorClass: "retryable"},
	}

	for _, result := range invalid {
		if err := ValidateDecisionEffectResult(result); !errors.Is(err, ErrInvalidDecisionContract) {
			t.Fatalf("ValidateDecisionEffectResult(%#v) error = %v, want ErrInvalidDecisionContract", result, err)
		}
	}
}

func TestDecisionRequestsOwnCallerFactsAndParameters(t *testing.T) {
	caller, fact, target := newDecisionRequestFixture(t)
	facts := []DecisionFactView{fact}

	factRequest, err := NewDecisionFactRequest(target, caller, facts)
	if err != nil {
		t.Fatalf("NewDecisionFactRequest() error = %v", err)
	}

	facts[0] = DecisionFactView{}

	if got := factRequest.Facts(); len(got) != 1 || got[0].ID() != "caller.principal" {
		t.Fatalf("Facts() = %#v, want owned fact view", got)
	}

	parameters := map[string]DecisionValue{"recipient": mustDecisionStringValue(t, "ops")}

	effectRequest, err := NewDecisionEffectRequest(DecisionEffectRequestInput{
		Parameters: parameters,
		Facts:      factRequest.Facts(),
		Target:     target,
		Caller:     caller,
		Effect:     "notify",
	})
	if err != nil {
		t.Fatalf("NewDecisionEffectRequest() error = %v", err)
	}

	delete(parameters, "recipient")

	if _, exists := effectRequest.Parameter("recipient"); !exists {
		t.Fatal("effect request did not own parameters")
	}

	parametersCopy := effectRequest.Parameters()
	delete(parametersCopy, "recipient")

	if _, exists := effectRequest.Parameter("recipient"); !exists {
		t.Fatal("Parameters() exposed mutable storage")
	}

	if effectRequest.Effect() != "notify" || effectRequest.Target() != target {
		t.Fatalf("effect request identity = %q, %#v, want notify and exact target", effectRequest.Effect(), effectRequest.Target())
	}
}

// newDecisionRequestFixture constructs immutable redacted request views for ownership tests.
func newDecisionRequestFixture(t *testing.T) (DecisionCallerView, DecisionFactView, DecisionTargetSelector) {
	t.Helper()

	caller, err := NewDecisionCallerView(DecisionCallerViewInput{
		Principal:          "operator@example.test",
		ClientID:           "management",
		AuthenticationKind: "oauth2",
		Scopes:             []string{"policy:decide"},
	})
	if err != nil {
		t.Fatalf("NewDecisionCallerView() error = %v", err)
	}

	fact, err := NewDecisionFactView(DecisionFactViewInput{
		ID:       "caller.principal",
		Category: DecisionFactCategoryEnvironment,
		Value:    mustDecisionStringValue(t, "operator@example.test"),
	})
	if err != nil {
		t.Fatalf("NewDecisionFactView() error = %v", err)
	}

	return caller, fact, DecisionTargetSelector{Namespace: "mail.security", Action: "evaluate"}
}

func TestDecisionCallerViewRejectsUnboundedIdentityAndScopes(t *testing.T) {
	valid := DecisionCallerViewInput{
		Principal:          "operator@example.test",
		AuthenticationKind: "oauth2",
	}

	tests := []struct {
		name   string
		mutate func(*DecisionCallerViewInput)
	}{
		{name: "empty principal", mutate: func(input *DecisionCallerViewInput) { input.Principal = "" }},
		{name: "long principal", mutate: func(input *DecisionCallerViewInput) { input.Principal = strings.Repeat("x", 513) }},
		{name: "long client", mutate: func(input *DecisionCallerViewInput) { input.ClientID = strings.Repeat("x", 513) }},
		{name: "empty authentication", mutate: func(input *DecisionCallerViewInput) { input.AuthenticationKind = "" }},
		{name: "many scopes", mutate: func(input *DecisionCallerViewInput) {
			input.Scopes = make([]string, 65)
			for index := range input.Scopes {
				input.Scopes[index] = "scope:" + strings.Repeat("x", index+1)
			}
		}},
		{name: "long scope", mutate: func(input *DecisionCallerViewInput) { input.Scopes = []string{strings.Repeat("x", 513)} }},
		{name: "duplicate scope", mutate: func(input *DecisionCallerViewInput) { input.Scopes = []string{"policy:decide", "policy:decide"} }},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := valid
			testCase.mutate(&candidate)

			if _, err := NewDecisionCallerView(candidate); !errors.Is(err, ErrInvalidDecisionContract) {
				t.Fatalf("NewDecisionCallerView() error = %v, want ErrInvalidDecisionContract", err)
			}
		})
	}
}

func validDecisionFactProviderDescriptor(t *testing.T) DecisionFactProviderDescriptor {
	t.Helper()

	return DecisionFactProviderDescriptor{
		Namespace: "mail.security",
		Name:      "risk",
		Targets: []DecisionTargetSelector{
			{Namespace: "mail.security", Action: "evaluate"},
		},
		Outputs: []DecisionFactOutputDescriptor{
			{
				Name:      "risk.score",
				Category:  DecisionFactCategoryEnvironment,
				Kind:      DecisionValueKindString,
				MaxLength: 64,
			},
		},
		Timeout: time.Second,
	}
}

func validDecisionEffectProviderDescriptor() DecisionEffectProviderDescriptor {
	return DecisionEffectProviderDescriptor{
		Namespace: "mail.security",
		Name:      "notifier",
		Effects: []DecisionEffectDescriptor{
			{
				Name:      "notify",
				Execution: DecisionEffectExecutionHostSync,
				Targets: []DecisionTargetSelector{
					{Namespace: "mail.security", Action: "evaluate"},
				},
				Parameters: []DecisionEffectParameterDescriptor{
					{
						Name:           "recipient",
						Kind:           DecisionValueKindString,
						MaxLength:      64,
						AllowedStrings: []string{"ops", "security"},
						NonEmpty:       true,
						Required:       true,
					},
				},
			},
		},
	}
}

func mustDecisionStringValue(t *testing.T, value string) DecisionValue {
	t.Helper()

	result, err := NewDecisionValue(DecisionValueInput{String: &value})
	if err != nil {
		t.Fatalf("NewDecisionValue(string) error = %v", err)
	}

	return result
}

func mustDecisionBooleanValue(t *testing.T, value bool) DecisionValue {
	t.Helper()

	result, err := NewDecisionValue(DecisionValueInput{Boolean: &value})
	if err != nil {
		t.Fatalf("NewDecisionValue(boolean) error = %v", err)
	}

	return result
}

// cloneDecisionFactProviderDescriptor detaches nested slices for mutation tests.
func cloneDecisionFactProviderDescriptor(input DecisionFactProviderDescriptor) DecisionFactProviderDescriptor {
	result := input
	result.Targets = append([]DecisionTargetSelector(nil), input.Targets...)
	result.Outputs = append([]DecisionFactOutputDescriptor(nil), input.Outputs...)

	return result
}

// cloneDecisionEffectProviderDescriptor detaches nested slices for mutation tests.
func cloneDecisionEffectProviderDescriptor(input DecisionEffectProviderDescriptor) DecisionEffectProviderDescriptor {
	result := input

	result.Effects = append([]DecisionEffectDescriptor(nil), input.Effects...)
	for index := range result.Effects {
		result.Effects[index].Targets = append([]DecisionTargetSelector(nil), input.Effects[index].Targets...)

		result.Effects[index].Parameters = append([]DecisionEffectParameterDescriptor(nil), input.Effects[index].Parameters...)
		for parameterIndex := range result.Effects[index].Parameters {
			result.Effects[index].Parameters[parameterIndex].AllowedStrings = append(
				[]string(nil),
				input.Effects[index].Parameters[parameterIndex].AllowedStrings...,
			)
		}
	}

	return result
}

// assertExactExportedFields checks the frozen value-only result shape.
func assertExactExportedFields(t *testing.T, contractType reflect.Type, want []string) {
	t.Helper()

	var got []string

	for index := range contractType.NumField() {
		field := contractType.Field(index)
		if field.IsExported() {
			got = append(got, field.Name)
		}
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s exported fields = %#v, want %#v", contractType, got, want)
	}
}

// assertNoForbiddenDecisionFields rejects extension-owned authority controls.
func assertNoForbiddenDecisionFields(t *testing.T, contractType reflect.Type) {
	t.Helper()

	forbidden := []string{
		"abort",
		"activation",
		"decision",
		"dedup",
		"detach",
		"gate",
		"host",
		"idempot",
		"planorder",
		"replay",
		"response",
		"retry",
		"schedule",
		"trustedfact",
	}

	for index := range contractType.NumField() {
		field := contractType.Field(index)
		if !field.IsExported() {
			continue
		}

		name := strings.ToLower(field.Name)
		for _, fragment := range forbidden {
			if strings.Contains(name, fragment) {
				t.Fatalf("%s exposes forbidden authority field %s", contractType, field.Name)
			}
		}
	}
}
