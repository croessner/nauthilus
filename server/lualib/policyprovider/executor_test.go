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
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/lualib/policyprovider"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

const policyProviderFixtureDirectory = "../../../testdata/lua/policyprovider/"

func TestLuaFactCollectorUsesRestrictedFreshStateAndStrictTypedValues(t *testing.T) {
	script := mustCompileFixture(t, "typed_callbacks.lua")
	descriptor := typedFactDescriptor()

	collector, err := policyprovider.NewLuaFactCollector(t.Context(), script, descriptor)
	if err != nil {
		t.Fatalf("NewLuaFactCollector() error = %v", err)
	}

	descriptor.Outputs[0].Name = "mutated"
	if got := collector.Descriptor().Outputs[0].Name; got != "risk.label" {
		t.Fatalf("Descriptor().Outputs[0].Name = %q, want risk.label", got)
	}

	for invocation := range 2 {
		result, collectErr := collector.Collect(t.Context(), validFactRequest(t))
		if collectErr != nil {
			t.Fatalf("Collect(%d) error = %v", invocation, collectErr)
		}

		if err = collector.Descriptor().ValidateResult(result); err != nil {
			t.Fatalf("ValidateResult(%d) error = %v", invocation, err)
		}

		assertTypedFactResult(t, result)
	}
}

func TestLuaEffectExecutorRunsOnlySelectedTypedEffect(t *testing.T) {
	script := mustCompileFixture(t, "typed_callbacks.lua")
	descriptor := typedEffectDescriptor()

	executor, err := policyprovider.NewLuaEffectExecutor(t.Context(), script, descriptor)
	if err != nil {
		t.Fatalf("NewLuaEffectExecutor() error = %v", err)
	}

	descriptor.Effects[0].Parameters[0].AllowedStrings[0] = "mutated"
	if got := executor.Descriptor().Effects[0].Parameters[0].AllowedStrings[0]; got != "accepted" {
		t.Fatalf("Descriptor() allowed string = %q, want accepted", got)
	}

	result, err := executor.Execute(t.Context(), validEffectRequest(t))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if result.State != policyprovider.EffectStateSucceeded || result.ErrorClass != "" {
		t.Fatalf("Execute() result = %#v", result)
	}

	invalid := validEffectRequest(t)
	invalid.Effect = "mail/unselected"

	if _, err = executor.Execute(t.Context(), invalid); !errors.Is(err, policyprovider.ErrCallbackInput) {
		t.Fatalf("Execute(unselected) error = %v, want ErrCallbackInput", err)
	}
}

func TestLuaCallbackViolationsHaveStableSecretSafeClasses(t *testing.T) {
	t.Run("script", func(t *testing.T) {
		_, err := policyprovider.CompileScript("invalid", []byte(`error("compile-secret"`))
		assertErrorClassWithoutSecret(t, err, policyprovider.ErrScriptPreparation, "compile-secret")
	})

	t.Run("registration", func(t *testing.T) {
		script, err := policyprovider.CompileScript("missing", []byte("return true"))
		if err != nil {
			t.Fatalf("CompileScript() error = %v", err)
		}

		_, err = policyprovider.NewLuaFactCollector(t.Context(), script, typedFactDescriptor())
		assertErrorClassWithoutSecret(t, err, policyprovider.ErrCallbackRegistration, "")
	})

	t.Run("result", func(t *testing.T) {
		script := mustCompileFixture(t, "invalid_authority.lua")

		collector, err := policyprovider.NewLuaFactCollector(t.Context(), script, typedFactDescriptor())
		if err != nil {
			t.Fatalf("NewLuaFactCollector() error = %v", err)
		}

		_, err = collector.Collect(t.Context(), validFactRequest(t))
		assertErrorClassWithoutSecret(t, err, policyprovider.ErrInvalidResult, "permit")
	})

	t.Run("callback", func(t *testing.T) {
		script := mustCompileFixture(t, "secret_error.lua")

		collector, err := policyprovider.NewLuaFactCollector(t.Context(), script, typedFactDescriptor())
		if err != nil {
			t.Fatalf("NewLuaFactCollector() error = %v", err)
		}

		result, err := collector.Collect(t.Context(), validFactRequest(t))
		assertErrorClassWithoutSecret(t, err, policyprovider.ErrCallbackExecution, "provider-secret")

		if result.ErrorClass != policyprovider.ErrorClassInternal {
			t.Fatalf("Collect() error class = %q, want internal", result.ErrorClass)
		}

		executor, err := policyprovider.NewLuaEffectExecutor(t.Context(), script, typedEffectDescriptor())
		if err != nil {
			t.Fatalf("NewLuaEffectExecutor() error = %v", err)
		}

		effectResult, err := executor.Execute(t.Context(), validEffectRequest(t))
		assertErrorClassWithoutSecret(t, err, policyprovider.ErrCallbackExecution, "effect-secret")

		if effectResult.State != policyprovider.EffectStateOutcomeUnknown || effectResult.ErrorClass != policyprovider.ErrorClassInternal {
			t.Fatalf("Execute() result = %#v", effectResult)
		}
	})
}

func TestLuaFactCollectorHonorsDeadline(t *testing.T) {
	script := mustCompileFixture(t, "cancelled.lua")

	collector, err := policyprovider.NewLuaFactCollector(t.Context(), script, typedFactDescriptor())
	if err != nil {
		t.Fatalf("NewLuaFactCollector() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	result, collectErr := collector.Collect(ctx, validFactRequest(t))
	if !errors.Is(collectErr, context.DeadlineExceeded) || !errors.Is(collectErr, policyprovider.ErrCallbackExecution) {
		t.Fatalf("Collect() error = %v, want callback execution deadline", collectErr)
	}

	if result.ErrorClass != policyprovider.ErrorClassTimeout {
		t.Fatalf("Collect() error class = %q, want timeout", result.ErrorClass)
	}
}

func TestLuaEffectExecutorReturnsOutcomeUnknownAfterDeadline(t *testing.T) {
	script := mustCompileFixture(t, "cancelled.lua")

	executor, err := policyprovider.NewLuaEffectExecutor(t.Context(), script, typedEffectDescriptor())
	if err != nil {
		t.Fatalf("NewLuaEffectExecutor() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	result, executeErr := executor.Execute(ctx, validEffectRequest(t))
	if !errors.Is(executeErr, context.DeadlineExceeded) || !errors.Is(executeErr, policyprovider.ErrCallbackExecution) {
		t.Fatalf("Execute() error = %v, want callback execution deadline", executeErr)
	}

	if result.State != policyprovider.EffectStateOutcomeUnknown || result.ErrorClass != policyprovider.ErrorClassTimeout {
		t.Fatalf("Execute() result = %#v", result)
	}
}

func TestLuaFactCollectorHonorsCancellation(t *testing.T) {
	script := mustCompileFixture(t, "cancelled.lua")

	collector, err := policyprovider.NewLuaFactCollector(t.Context(), script, typedFactDescriptor())
	if err != nil {
		t.Fatalf("NewLuaFactCollector() error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	result, collectErr := collector.Collect(ctx, validFactRequest(t))
	if !errors.Is(collectErr, context.Canceled) || !errors.Is(collectErr, policyprovider.ErrCallbackExecution) {
		t.Fatalf("Collect() error = %v, want callback cancellation", collectErr)
	}

	if result.ErrorClass != policyprovider.ErrorClassInternal {
		t.Fatalf("Collect() error class = %q, want internal", result.ErrorClass)
	}
}

// mustCompileFixture compiles one hermetic generic policy-provider Lua fixture.
func mustCompileFixture(t *testing.T, name string) *policyprovider.Script {
	t.Helper()

	path := policyProviderFixtureDirectory + name

	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy provider fixture %q: %v", name, err)
	}

	script, err := policyprovider.CompileScript(path, source)
	if err != nil {
		t.Fatalf("CompileScript(%q) error = %v", name, err)
	}

	return script
}

// typedFactDescriptor declares every strict value kind used by the callback fixture.
func typedFactDescriptor() policyprovider.FactProviderDescriptor {
	return policyprovider.FactProviderDescriptor{
		Namespace: "mail",
		Name:      "reputation",
		Targets:   []policyprovider.TargetSelector{{Namespace: "mail", Action: "deliver"}},
		Outputs: []policyprovider.FactOutputDescriptor{
			{Name: "risk.label", Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindString, MaxLength: 64},
			{Name: "risk.allowed", Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindBoolean},
			{Name: "risk.score", Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindInteger},
			{Name: "risk.ratio", Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindDouble},
			{Name: "risk.tags", Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindStrings, MaxLength: 64, MaxItems: 4},
			{Name: "risk.digest", Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindBytes, MaxBytes: 16},
			{Name: "risk.observed_at", Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindTimestamp},
			{Name: "runtime.invocations", Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindInteger},
		},
		Timeout: 100 * time.Millisecond,
	}
}

// typedEffectDescriptor declares one selected synchronous effect with a strict parameter.
func typedEffectDescriptor() policyprovider.EffectProviderDescriptor {
	return policyprovider.EffectProviderDescriptor{
		Namespace: "mail",
		Name:      "audit",
		Effects: []policyprovider.EffectDescriptor{{
			Name:      "record-audit",
			Targets:   []policyprovider.TargetSelector{{Namespace: "mail", Action: "deliver"}},
			Execution: policyprovider.EffectExecutionHostSync,
			Parameters: []policyprovider.ParameterDescriptor{{
				Name:           "message",
				Kind:           decision.ValueKindString,
				MaxLength:      32,
				AllowedStrings: []string{"accepted", "rejected"},
				NonEmpty:       true,
				Required:       true,
			}},
		}},
	}
}

// validFactRequest creates one target-aware request with constructed strict input.
func validFactRequest(t *testing.T) policyprovider.FactRequest {
	t.Helper()

	return policyprovider.FactRequest{
		Target: policyprovider.TargetSelector{Namespace: "mail", Action: "deliver"},
		Caller: policyprovider.CallerView{
			Principal:          "mail-gateway",
			ClientID:           "smtp-edge",
			AuthenticationKind: "private_key_jwt",
			Scopes:             []string{"policy.evaluate"},
		},
		Facts: []policyprovider.FactView{{
			ID:       "nauthilus.request.score",
			Category: decision.FactCategoryEnvironment,
			Value:    mustIntegerValue(t, 41),
		}},
	}
}

// validEffectRequest creates one policy-selected exact effect request.
func validEffectRequest(t *testing.T) policyprovider.EffectRequest {
	t.Helper()

	return policyprovider.EffectRequest{
		Target: policyprovider.TargetSelector{Namespace: "mail", Action: "deliver"},
		Caller: policyprovider.CallerView{
			Principal:          "mail-gateway",
			ClientID:           "smtp-edge",
			AuthenticationKind: "private_key_jwt",
			Scopes:             []string{"policy.evaluate"},
		},
		Effect: "mail/record-audit",
		Parameters: []policyprovider.EffectParameter{{
			Name:  "message",
			Value: mustExecutorStringValue(t, "accepted"),
		}},
	}
}

// assertTypedFactResult verifies all strict values and fresh-state isolation.
func assertTypedFactResult(t *testing.T, result policyprovider.FactResult) {
	t.Helper()

	facts := make(map[string]decision.Value, len(result.Facts))
	for _, fact := range result.Facts {
		facts[fact.Name] = fact.Value
	}

	assertTypedScalarFacts(t, facts)
	assertTypedCollectionFacts(t, facts)
	assertTypedTemporalFacts(t, facts)
}

// assertTypedScalarFacts verifies exact scalar callback output members.
func assertTypedScalarFacts(t *testing.T, facts map[string]decision.Value) {
	t.Helper()

	if got, _ := facts["risk.label"].StringValue(); got != "trusted" {
		t.Fatalf("risk.label = %q, want trusted", got)
	}

	if got, _ := facts["risk.allowed"].Boolean(); !got {
		t.Fatal("risk.allowed = false, want true")
	}

	if got, _ := facts["risk.score"].Integer(); got != 42 {
		t.Fatalf("risk.score = %d, want 42", got)
	}

	if got, _ := facts["risk.ratio"].Double(); got != 0.5 {
		t.Fatalf("risk.ratio = %f, want 0.5", got)
	}
}

// assertTypedCollectionFacts verifies ordered string-list and byte members.
func assertTypedCollectionFacts(t *testing.T, facts map[string]decision.Value) {
	t.Helper()

	if got, _ := facts["risk.tags"].Strings(); len(got) != 2 || got[0] != "mx" || got[1] != "trusted" {
		t.Fatalf("risk.tags = %#v", got)
	}

	if got, _ := facts["risk.digest"].Bytes(); len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 2 {
		t.Fatalf("risk.digest = %#v", got)
	}
}

// assertTypedTemporalFacts verifies timestamps and request-state isolation.
func assertTypedTemporalFacts(t *testing.T, facts map[string]decision.Value) {
	t.Helper()

	wantTime := time.Date(2026, time.August, 25, 8, 30, 0, 123456789, time.UTC)
	if got, _ := facts["risk.observed_at"].Timestamp(); !got.Equal(wantTime) {
		t.Fatalf("risk.observed_at = %s, want %s", got, wantTime)
	}

	if got, _ := facts["runtime.invocations"].Integer(); got != 1 {
		t.Fatalf("runtime.invocations = %d, want fresh-state value 1", got)
	}
}

// assertErrorClassWithoutSecret verifies stable error taxonomy without callback text disclosure.
func assertErrorClassWithoutSecret(t *testing.T, err error, class error, secret string) {
	t.Helper()

	if !errors.Is(err, class) {
		t.Fatalf("error = %v, want class %v", err, class)
	}

	if secret != "" && strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked secret %q: %v", secret, err)
	}
}

// mustExecutorStringValue constructs one strict string test value.
func mustExecutorStringValue(t *testing.T, input string) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return value
}

// mustIntegerValue constructs one strict integer test value.
func mustIntegerValue(t *testing.T, input int64) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{Integer: &input})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return value
}
