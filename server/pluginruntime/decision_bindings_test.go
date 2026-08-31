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

package pluginruntime

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	testNativeDecisionFactComponent   = "risk"
	testNativeDecisionFactID          = "plugin.riskmod.risk.score"
	testNativeDecisionFactProviderID  = "mail/plugin.riskmod.risk"
	testNativeDecisionModule          = "riskmod"
	testNativeDecisionNamespace       = "mail"
	testNativeDecisionPostEffectID    = "mail/archive"
	testNativeDecisionSyncEffectID    = "mail/notify"
	testNativeDecisionEffectComponent = "notifier"
	testNativeDecisionEffectProvider  = "mail/plugin.riskmod.notifier"
)

// TestPrepareDecisionBindingsResolvesOnlyConfiguredGenericComponents proves generation-local activation.
func TestPrepareDecisionBindingsResolvesOnlyConfiguredGenericComponents(t *testing.T) {
	factProvider := &recordingDecisionFactProvider{descriptor: nativeDecisionFactDescriptor()}
	effectProvider := &recordingDecisionEffectProvider{descriptor: nativeDecisionEffectDescriptor()}
	bindings := nativeDecisionGenerationBindings(factProvider, effectProvider)

	prepared, err := bindings.PrepareDecisionBindings(t.Context(), DecisionBindingInput{
		FactProviders: []DecisionFactBindingInput{{
			Definition: nativeDecisionFactDefinition(t), ModuleName: testNativeDecisionModule,
			ComponentName: testNativeDecisionFactComponent,
		}},
		EffectProviders: []DecisionEffectBindingInput{{
			Definition: nativeDecisionEffectProviderDefinition(t), Effects: nativeDecisionEffectDefinitions(t),
			ModuleName: testNativeDecisionModule, ComponentName: testNativeDecisionEffectComponent,
		}},
	})
	if err != nil {
		t.Fatalf("PrepareDecisionBindings() error = %v", err)
	}

	if got := prepared.FactProviders(); len(got) != 1 || got[testNativeDecisionFactProviderID].Provider == nil {
		t.Fatalf("fact bindings = %#v, want only configured generic provider", got)
	}

	if got := prepared.SyncEffects(); len(got) != 1 || got[testNativeDecisionEffectProvider] == nil {
		t.Fatalf("sync bindings = %#v, want configured effect provider", got)
	}

	if got := prepared.PostActions(); len(got) != 1 || got[testNativeDecisionEffectProvider] == nil {
		t.Fatalf("post bindings = %#v, want configured effect provider", got)
	}

	returned := prepared.FactProviders()
	delete(returned, testNativeDecisionFactProviderID)

	if len(prepared.FactProviders()) != 1 {
		t.Fatal("prepared fact map exposed mutable storage")
	}

	if factProvider.callCount() != 0 || effectProvider.callCount() != 0 {
		t.Fatal("generation preparation invoked a provider")
	}
}

// TestPrepareDecisionBindingsRejectsMissingAndMismatchedCapabilities proves exact frozen resolution.
func TestPrepareDecisionBindingsRejectsMissingAndMismatchedCapabilities(t *testing.T) {
	bindings := nativeDecisionGenerationBindings(
		&recordingDecisionFactProvider{descriptor: nativeDecisionFactDescriptor()},
		&recordingDecisionEffectProvider{descriptor: nativeDecisionEffectDescriptor()},
	)

	tests := []struct {
		input DecisionBindingInput
		name  string
	}{
		{
			name: "unregistered component",
			input: DecisionBindingInput{FactProviders: []DecisionFactBindingInput{{
				Definition: nativeDecisionFactDefinition(t), ModuleName: testNativeDecisionModule,
				ComponentName: "missing",
			}}},
		},
		{
			name: "foreign provider identity",
			input: DecisionBindingInput{FactProviders: []DecisionFactBindingInput{{
				Definition: nativeDecisionFactDefinitionWithID(t, "mail/plugin.foreign.risk"),
				ModuleName: testNativeDecisionModule, ComponentName: testNativeDecisionFactComponent,
			}}},
		},
		{
			name: "duplicate selection",
			input: DecisionBindingInput{FactProviders: []DecisionFactBindingInput{
				{Definition: nativeDecisionFactDefinition(t), ModuleName: testNativeDecisionModule, ComponentName: testNativeDecisionFactComponent},
				{Definition: nativeDecisionFactDefinition(t), ModuleName: testNativeDecisionModule, ComponentName: testNativeDecisionFactComponent},
			}},
		},
		{
			name: "effect provider with fact schedule",
			input: DecisionBindingInput{EffectProviders: []DecisionEffectBindingInput{{
				Definition: nativeDecisionScheduledEffectProviderDefinition(t), Effects: nativeDecisionEffectDefinitions(t),
				ModuleName: testNativeDecisionModule, ComponentName: testNativeDecisionEffectComponent,
			}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := bindings.PrepareDecisionBindings(t.Context(), test.input); !errors.Is(err, ErrInvalidDecisionBinding) {
				t.Fatalf("PrepareDecisionBindings() error = %v, want ErrInvalidDecisionBinding", err)
			}
		})
	}
}

// TestNativeDecisionFactBindingBuildsBoundedTargetAwareRequest proves request and result adaptation.
func TestNativeDecisionFactBindingBuildsBoundedTargetAwareRequest(t *testing.T) {
	provider := &recordingDecisionFactProvider{
		descriptor: nativeDecisionFactDescriptor(),
		result: pluginapi.DecisionFactResult{Facts: []pluginapi.DecisionFactOutput{{
			Name: "risk.score", Value: mustPluginDecisionStringValue(t, "high"),
		}}},
	}
	observer := &recordingPluginObserver{}
	prepared := mustPrepareNativeDecisionBindings(t, provider, &recordingDecisionEffectProvider{
		descriptor: nativeDecisionEffectDescriptor(),
	}, observer)

	binding := prepared.FactProviders()[testNativeDecisionFactProviderID]
	assertNativeDecisionFactBinding(t, binding)

	facts := mustCollectNativeDecisionFacts(t, binding.Provider)
	assertNativeDecisionFacts(t, facts)

	request, deadline := provider.lastFactCall()
	assertNativeDecisionFactRequest(t, request, deadline)
	assertNativeDecisionFactObservation(t, observer)
}

func TestNativeDecisionValueAdapterPreservesPresentEmptyStrings(t *testing.T) {
	pluginValue, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Strings: []string{}})
	if err != nil {
		t.Fatalf("NewDecisionValue(empty strings) error = %v", err)
	}

	internal, err := nativeDecisionValue(pluginValue)
	if err != nil {
		t.Fatalf("nativeDecisionValue(empty strings) error = %v", err)
	}

	internalStrings, ok := internal.Strings()
	if !ok || internalStrings == nil || len(internalStrings) != 0 {
		t.Fatalf("internal Strings() = %#v, %t, want non-nil empty list", internalStrings, ok)
	}

	roundTrip, err := pluginDecisionValue(internal)
	if err != nil {
		t.Fatalf("pluginDecisionValue(empty strings) error = %v", err)
	}

	pluginStrings, ok := roundTrip.Strings()
	if !ok || pluginStrings == nil || len(pluginStrings) != 0 {
		t.Fatalf("round-trip Strings() = %#v, %t, want non-nil empty list", pluginStrings, ok)
	}
}

// assertNativeDecisionFactBinding verifies frozen internal provenance authority.
func assertNativeDecisionFactBinding(t *testing.T, binding policyruntime.FactProviderBinding) {
	t.Helper()

	if binding.Source != decision.FactSourcePlugin || binding.Authority != testNativeDecisionModule ||
		binding.Component != testNativeDecisionFactProviderID {
		t.Fatalf("fact provenance binding = %#v", binding)
	}
}

// mustCollectNativeDecisionFacts invokes the configured provider and requires success.
func mustCollectNativeDecisionFacts(
	t *testing.T,
	provider policyruntime.FactProvider,
) []policyruntime.ProvidedFact {
	t.Helper()

	facts, err := provider.Collect(t.Context(), nativeDecisionFactInput(t, nativeDecisionTarget(t)))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	return facts
}

// assertNativeDecisionFacts verifies the qualified fact returned through the adapter.
func assertNativeDecisionFacts(t *testing.T, facts []policyruntime.ProvidedFact) {
	t.Helper()

	if len(facts) != 1 || facts[0].ID() != testNativeDecisionFactID ||
		facts[0].Category() != decision.FactCategoryEnvironment {
		t.Fatalf("provided facts = %#v, want qualified plugin fact", facts)
	}
}

// assertNativeDecisionFactRequest verifies target, caller, facts, and deadline bounds.
func assertNativeDecisionFactRequest(
	t *testing.T,
	request pluginapi.DecisionFactRequest,
	deadline time.Time,
) {
	t.Helper()

	wantTarget := pluginapi.DecisionTargetSelector{Namespace: "mail", Action: "filter"}
	if request.Target() != wantTarget {
		t.Fatalf("request target = %#v, want %#v", request.Target(), wantTarget)
	}

	if request.Caller().Principal() != "policy-client" || len(request.Facts()) != 1 {
		t.Fatalf("request caller/facts = %#v/%#v", request.Caller(), request.Facts())
	}

	if deadline.IsZero() || time.Until(deadline) > nativeDecisionFactDefinition(t).Timeout() {
		t.Fatalf("provider deadline = %v, want bounded deadline", deadline)
	}
}

// assertNativeDecisionFactObservation verifies one bounded fact-provider record.
func assertNativeDecisionFactObservation(t *testing.T, observer *recordingPluginObserver) {
	t.Helper()

	records := observer.records()
	if len(records) != 1 ||
		records[0].ExtensionPoint != string(pluginregistry.ComponentKindDecisionFactProvider) {
		t.Fatalf("observer records = %#v", records)
	}
}

// TestNativeDecisionFactBindingLimitsRegisteredTargetsToConfiguredAuthority proves configuration narrows capability.
func TestNativeDecisionFactBindingLimitsRegisteredTargetsToConfiguredAuthority(t *testing.T) {
	descriptor := nativeDecisionFactDescriptor()
	descriptor.Targets = append(descriptor.Targets, pluginapi.DecisionTargetSelector{
		Namespace: testNativeDecisionNamespace,
		Action:    "other",
	})
	provider := &recordingDecisionFactProvider{descriptor: descriptor}
	prepared := mustPrepareNativeDecisionBindings(t, provider, &recordingDecisionEffectProvider{
		descriptor: nativeDecisionEffectDescriptor(),
	}, nil)
	binding := prepared.FactProviders()[testNativeDecisionFactProviderID]

	tests := []struct {
		wantErr   error
		name      string
		action    string
		wantCalls int
	}{
		{name: "configured target", action: "filter", wantCalls: 1},
		{
			name: "registered but unconfigured target", action: "other",
			wantErr: policyruntime.ErrProviderContractViolation, wantCalls: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := binding.Provider.Collect(
				t.Context(),
				nativeDecisionFactInput(t, mustNativeDecisionTarget(t, testNativeDecisionNamespace, test.action)),
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Collect() error = %v, want %v", err, test.wantErr)
			}

			if got := provider.callCount(); got != test.wantCalls {
				t.Fatalf("provider calls = %d, want %d", got, test.wantCalls)
			}
		})
	}
}

// TestNativeDecisionFactBindingContainsFailures proves target, panic, result, and cancellation containment.
func TestNativeDecisionFactBindingContainsFailures(t *testing.T) {
	for _, test := range nativeDecisionFactFailureCases(t) {
		t.Run(test.name, test.run)
	}
}

type nativeDecisionFactInputKind uint8

const (
	nativeDecisionConfiguredFactInput nativeDecisionFactInputKind = iota
	nativeDecisionForeignFactInput
	nativeDecisionExistingFactInput
)

type nativeDecisionFactFailureCase struct {
	result       pluginapi.DecisionFactResult
	err          error
	panicValue   any
	want         error
	name         string
	inputKind    nativeDecisionFactInputKind
	expectNoCall bool
}

// nativeDecisionFactFailureCases defines bounded provider failure and authority scenarios.
func nativeDecisionFactFailureCases(t *testing.T) []nativeDecisionFactFailureCase {
	t.Helper()

	validValue := mustPluginDecisionStringValue(t, "high")
	wrongValue := mustPluginDecisionBooleanValue(t, true)

	return []nativeDecisionFactFailureCase{
		{
			name: "foreign target", inputKind: nativeDecisionForeignFactInput,
			want: policyruntime.ErrProviderContractViolation, expectNoCall: true,
		},
		{
			name: "wrong result kind", want: policyruntime.ErrProviderContractViolation,
			result: pluginapi.DecisionFactResult{Facts: []pluginapi.DecisionFactOutput{{Name: "risk.score", Value: wrongValue}}},
		},
		{
			name: "undeclared result", want: policyruntime.ErrProviderContractViolation,
			result: pluginapi.DecisionFactResult{Facts: []pluginapi.DecisionFactOutput{{Name: "risk.undeclared", Value: validValue}}},
		},
		{
			name: "duplicate result", want: policyruntime.ErrProviderContractViolation,
			result: pluginapi.DecisionFactResult{Facts: []pluginapi.DecisionFactOutput{
				{Name: "risk.score", Value: validValue}, {Name: "risk.score", Value: validValue},
			}},
		},
		{
			name: "existing fact collision", inputKind: nativeDecisionExistingFactInput,
			result: pluginapi.DecisionFactResult{Facts: []pluginapi.DecisionFactOutput{{Name: "risk.score", Value: validValue}}},
			want:   policyruntime.ErrProviderContractViolation,
		},
		{
			name: "classified failure", result: pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassUnavailable},
			want: errDecisionProviderFailure,
		},
		{
			name: "classified timeout", result: pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassTimeout},
			want: context.DeadlineExceeded,
		},
		{name: "raw error", err: errors.New("secret-value"), want: errDecisionProviderInternal},
		{name: "panic", panicValue: "secret-value", want: policyruntime.ErrProviderContractViolation},
		{name: "provider cancellation error without host cancellation", err: context.Canceled, want: errDecisionProviderInternal},
	}
}

// run verifies one provider failure mapping without duplicating binding setup.
func (test nativeDecisionFactFailureCase) run(t *testing.T) {
	provider := &recordingDecisionFactProvider{
		descriptor: nativeDecisionFactDescriptor(),
		result:     test.result,
		err:        test.err,
		panicValue: test.panicValue,
	}
	prepared := mustPrepareNativeDecisionBindings(t, provider, &recordingDecisionEffectProvider{
		descriptor: nativeDecisionEffectDescriptor(),
	}, nil)
	binding := prepared.FactProviders()[testNativeDecisionFactProviderID]

	_, err := binding.Provider.Collect(t.Context(), test.factInput(t))
	if !errors.Is(err, test.want) {
		t.Fatalf("Collect() error = %v, want %v", err, test.want)
	}

	if err != nil && containsSecret(err.Error()) {
		t.Fatalf("Collect() exposed panic/error text: %v", err)
	}

	wantCalls := 1
	if test.expectNoCall {
		wantCalls = 0
	}

	if got := provider.callCount(); got != wantCalls {
		t.Fatalf("provider calls = %d, want %d", got, wantCalls)
	}
}

// factInput constructs the authority scenario selected by a failure case.
func (test nativeDecisionFactFailureCase) factInput(t *testing.T) policyruntime.FactProviderInput {
	t.Helper()

	switch test.inputKind {
	case nativeDecisionForeignFactInput:
		return nativeDecisionFactInput(t, mustNativeDecisionTarget(t, "mail", "other"))
	case nativeDecisionExistingFactInput:
		return nativeDecisionCollisionFactInput(t)
	default:
		return nativeDecisionFactInput(t, nativeDecisionTarget(t))
	}
}

// TestNativeDecisionFactBindingCancellationOverridesApparentSuccess proves host cancellation wins.
func TestNativeDecisionFactBindingCancellationOverridesApparentSuccess(t *testing.T) {
	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: pointerTo("high")})
	if err != nil {
		t.Fatalf("NewDecisionValue() error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	provider := &recordingDecisionFactProvider{
		descriptor: nativeDecisionFactDescriptor(),
		result: pluginapi.DecisionFactResult{Facts: []pluginapi.DecisionFactOutput{{
			Name: "risk.score", Value: value,
		}}},
		onCollect: func(context.Context) { cancel() },
	}
	observer := &recordingPluginObserver{}
	prepared := mustPrepareNativeDecisionBindings(t, provider, &recordingDecisionEffectProvider{
		descriptor: nativeDecisionEffectDescriptor(),
	}, observer)

	binding := prepared.FactProviders()[testNativeDecisionFactProviderID]
	facts, err := binding.Provider.Collect(ctx, nativeDecisionFactInput(t, nativeDecisionTarget(t)))

	if !errors.Is(err, context.Canceled) || facts != nil || provider.callCount() != 1 {
		t.Fatalf("Collect() facts/error/calls = %#v/%v/%d", facts, err, provider.callCount())
	}

	records := observer.records()
	if len(records) != 1 || pluginCallResult(records[0]) != pluginCallResultCanceled {
		t.Fatalf("observer records = %#v, want effective canceled classification", records)
	}
}

// TestNativeDecisionEffectsInvokeOnlySelectedTypedEffects proves selection and closed result mapping.
func TestNativeDecisionEffectsInvokeOnlySelectedTypedEffects(t *testing.T) {
	provider := &recordingDecisionEffectProvider{
		descriptor: nativeDecisionEffectDescriptor(),
		result:     pluginapi.DecisionEffectResult{Outcome: pluginapi.DecisionEffectOutcomeSucceeded},
	}
	prepared := mustPrepareNativeDecisionBindings(t, &recordingDecisionFactProvider{
		descriptor: nativeDecisionFactDescriptor(),
	}, provider, nil)

	syncProvider := prepared.SyncEffects()[testNativeDecisionEffectProvider]
	result := syncProvider.Execute(t.Context(), nativeDecisionEffectExecution(t, testNativeDecisionSyncEffectID, 1))

	if result.State() != effectsupervisor.StateSucceeded || provider.callCount() != 1 {
		t.Fatalf("sync result/calls = %q/%d", result.State(), provider.callCount())
	}

	request := provider.lastEffectRequest()
	if request.Effect() != "notify" || request.Target().Action != "filter" {
		t.Fatalf("effect request = %#v/%#v", request.Effect(), request.Target())
	}

	unselected := nativeDecisionEffectExecution(t, "mail/unselected", 2)
	result = syncProvider.Execute(t.Context(), unselected)

	if result.State() != effectsupervisor.StateFailed || result.ErrorClass() != "invalid_input" {
		t.Fatalf("unselected result = %q/%q", result.State(), result.ErrorClass())
	}

	if provider.callCount() != 1 {
		t.Fatal("unselected effect invoked provider")
	}
}

// TestNativeDecisionEffectsRejectInvalidSelectedInputBeforeCallback proves typed host validation precedes invocation.
func TestNativeDecisionEffectsRejectInvalidSelectedInputBeforeCallback(t *testing.T) {
	provider := &recordingDecisionEffectProvider{
		descriptor: nativeDecisionEffectDescriptor(),
		result:     pluginapi.DecisionEffectResult{Outcome: pluginapi.DecisionEffectOutcomeSucceeded},
	}
	prepared := mustPrepareNativeDecisionBindings(t, &recordingDecisionFactProvider{
		descriptor: nativeDecisionFactDescriptor(),
	}, provider, nil)
	syncProvider := prepared.SyncEffects()[testNativeDecisionEffectProvider]
	wrongKind := nativeDecisionBooleanValue(t, true)

	tests := []struct {
		execution policyruntime.EffectExecution
		name      string
	}{
		{
			name: "wrong target",
			execution: nativeDecisionEffectExecutionWith(
				t, testNativeDecisionSyncEffectID, 1,
				mustNativeDecisionTarget(t, testNativeDecisionNamespace, "other"),
				map[string]decision.Value{"level": nativeDecisionStringValue(t, "security")},
			),
		},
		{
			name: "missing required level",
			execution: nativeDecisionEffectExecutionWith(
				t, testNativeDecisionSyncEffectID, 2, nativeDecisionTarget(t), nil,
			),
		},
		{
			name: "wrong level kind",
			execution: nativeDecisionEffectExecutionWith(
				t, testNativeDecisionSyncEffectID, 3, nativeDecisionTarget(t),
				map[string]decision.Value{"level": wrongKind},
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := syncProvider.Execute(t.Context(), test.execution)
			if result.State() != effectsupervisor.StateFailed || result.ErrorClass() != "invalid_input" {
				t.Fatalf("rejected result = %q/%q", result.State(), result.ErrorClass())
			}

			if got := provider.callCount(); got != 0 {
				t.Fatalf("rejected effect invoked provider: calls = %d, want 0", got)
			}
		})
	}
}

type nativeDecisionEffectOutcomeCase struct {
	result       pluginapi.DecisionEffectResult
	err          error
	panicValue   any
	wantState    effectsupervisor.State
	wantClass    string
	wantObserved string
	name         string
	wantCalls    int
	cancelBefore bool
	cancelDuring bool
	deadline     bool
}

// TestNativeDecisionEffectOutcomesDistinguishKnownAndAmbiguousAttempts proves closed no-retry mapping.
func TestNativeDecisionEffectOutcomesDistinguishKnownAndAmbiguousAttempts(t *testing.T) {
	for _, test := range nativeDecisionEffectOutcomeCases() {
		t.Run(test.name, test.run)
	}
}

// nativeDecisionEffectOutcomeCases combines closed and ambiguous attempt scenarios.
func nativeDecisionEffectOutcomeCases() []nativeDecisionEffectOutcomeCase {
	result := nativeDecisionClosedEffectOutcomeCases()

	return append(result, nativeDecisionAmbiguousEffectOutcomeCases()...)
}

// nativeDecisionClosedEffectOutcomeCases defines provider-controlled closed results.
func nativeDecisionClosedEffectOutcomeCases() []nativeDecisionEffectOutcomeCase {
	return []nativeDecisionEffectOutcomeCase{
		{
			name: "succeeded", result: pluginapi.DecisionEffectResult{Outcome: pluginapi.DecisionEffectOutcomeSucceeded},
			wantState: effectsupervisor.StateSucceeded, wantCalls: 1, wantObserved: pluginCallResultOK,
		},
		{
			name: "closed failed", result: pluginapi.DecisionEffectResult{
				Outcome: pluginapi.DecisionEffectOutcomeFailed, ErrorClass: pluginapi.DecisionErrorClassUnavailable,
			},
			wantState: effectsupervisor.StateFailed, wantClass: "unavailable", wantCalls: 1,
			wantObserved: pluginCallResultError,
		},
		{
			name: "closed unknown", result: pluginapi.DecisionEffectResult{
				Outcome: pluginapi.DecisionEffectOutcomeUnknown, ErrorClass: pluginapi.DecisionErrorClassTimeout,
			},
			wantState: effectsupervisor.StateOutcomeUnknown, wantClass: "timeout", wantCalls: 1,
			wantObserved: pluginCallResultError,
		},
		{
			name: "raw error after attempt", err: errors.New("secret-value"),
			wantState: effectsupervisor.StateFailed, wantClass: "internal", wantCalls: 1,
			wantObserved: pluginCallResultError,
		},
		{
			name: "provider cancellation error without host cancellation", err: context.Canceled,
			wantState: effectsupervisor.StateFailed, wantClass: "internal", wantCalls: 1,
			wantObserved: pluginCallResultError,
		},
	}
}

// nativeDecisionAmbiguousEffectOutcomeCases defines cancellation and uncertain attempt scenarios.
func nativeDecisionAmbiguousEffectOutcomeCases() []nativeDecisionEffectOutcomeCase {
	return []nativeDecisionEffectOutcomeCase{
		{
			name: "caller cancellation wins after attempt", err: errors.New("secret-value"), cancelDuring: true,
			wantState: effectsupervisor.StateOutcomeUnknown, wantClass: "canceled", wantCalls: 1,
			wantObserved: pluginCallResultCanceled,
		},
		{
			name:   "caller cancellation overrides apparent success",
			result: pluginapi.DecisionEffectResult{Outcome: pluginapi.DecisionEffectOutcomeSucceeded}, cancelDuring: true,
			wantState: effectsupervisor.StateOutcomeUnknown, wantClass: "canceled", wantCalls: 1,
			wantObserved: pluginCallResultCanceled,
		},
		{
			name: "caller cancellation overrides closed failure",
			result: pluginapi.DecisionEffectResult{
				Outcome: pluginapi.DecisionEffectOutcomeFailed, ErrorClass: pluginapi.DecisionErrorClassUnavailable,
			},
			cancelDuring: true,
			wantState:    effectsupervisor.StateOutcomeUnknown, wantClass: "canceled", wantCalls: 1,
			wantObserved: pluginCallResultCanceled,
		},
		{
			name:   "deadline overrides apparent success",
			result: pluginapi.DecisionEffectResult{Outcome: pluginapi.DecisionEffectOutcomeSucceeded}, deadline: true,
			wantState: effectsupervisor.StateOutcomeUnknown, wantClass: "timeout", wantCalls: 1,
			wantObserved: pluginCallResultTimeout,
		},
		{
			name: "panic after attempt", panicValue: "secret-value",
			wantState: effectsupervisor.StateFailed, wantClass: "panic", wantCalls: 1,
			wantObserved: pluginCallResultPanic,
		},
		{
			name:      "invalid result after attempt",
			wantState: effectsupervisor.StateFailed, wantClass: "invalid_result", wantCalls: 1,
			wantObserved: pluginCallResultError,
		},
		{
			name: "canceled before attempt", cancelBefore: true,
			wantState: effectsupervisor.StateFailed, wantClass: "canceled", wantCalls: 0,
			wantObserved: pluginCallResultCanceled,
		},
	}
}

// run executes and verifies one closed or ambiguous native effect outcome.
func (test nativeDecisionEffectOutcomeCase) run(t *testing.T) {
	ctx, cancel := test.callContext(t)
	defer cancel()

	provider := test.effectProvider(cancel)
	if test.cancelBefore {
		cancel()
	}

	observer := &recordingPluginObserver{}
	prepared := mustPrepareNativeDecisionBindings(t, &recordingDecisionFactProvider{
		descriptor: nativeDecisionFactDescriptor(),
	}, provider, observer)
	result := prepared.SyncEffects()[testNativeDecisionEffectProvider].Execute(
		ctx,
		nativeDecisionEffectExecution(t, testNativeDecisionSyncEffectID, 1),
	)

	test.assertEffectResult(t, result, provider.callCount())
	test.assertObservation(t, observer.records())
}

// callContext constructs the host cancellation mode for one outcome scenario.
func (test nativeDecisionEffectOutcomeCase) callContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()

	if test.deadline {
		return context.WithTimeout(t.Context(), 20*time.Millisecond)
	}

	return context.WithCancel(t.Context())
}

// effectProvider configures the callback behavior for one outcome scenario.
func (test nativeDecisionEffectOutcomeCase) effectProvider(cancel context.CancelFunc) *recordingDecisionEffectProvider {
	provider := &recordingDecisionEffectProvider{
		descriptor: nativeDecisionEffectDescriptor(),
		result:     test.result,
		err:        test.err,
		panicValue: test.panicValue,
	}

	if test.cancelDuring {
		provider.onExecute = func(context.Context) { cancel() }
	}

	if test.deadline {
		provider.onExecute = func(ctx context.Context) { <-ctx.Done() }
	}

	return provider
}

// assertEffectResult verifies the supervisor state and at-most-once attempt count.
func (test nativeDecisionEffectOutcomeCase) assertEffectResult(
	t *testing.T,
	result effectsupervisor.Result,
	callCount int,
) {
	t.Helper()

	if result.State() != test.wantState || result.ErrorClass() != test.wantClass || callCount != test.wantCalls {
		t.Fatalf(
			"effect state/class/calls = %q/%q/%d, want %q/%q/%d",
			result.State(), result.ErrorClass(), callCount,
			test.wantState, test.wantClass, test.wantCalls,
		)
	}
}

// assertObservation verifies bounded and secret-safe callback telemetry.
func (test nativeDecisionEffectOutcomeCase) assertObservation(t *testing.T, records []CallRecord) {
	t.Helper()

	if len(records) != 1 {
		t.Fatalf("bounded observer records = %#v", records)
	}

	record := records[0]
	if record.ModuleName != testNativeDecisionModule || record.ComponentName != testNativeDecisionEffectComponent ||
		record.Method != "Execute" || record.ExtensionPoint != string(pluginregistry.ComponentKindDecisionEffectProvider) {
		t.Fatalf("bounded observer record = %#v", record)
	}

	if record.Err != nil && containsSecret(record.Err.Error()) {
		t.Fatalf("observer exposed provider-controlled error: %v", record.Err)
	}

	if got := pluginCallResult(record); got != test.wantObserved {
		t.Fatalf("observer result = %q, want %q", got, test.wantObserved)
	}
}

// TestNativeDecisionPostActionDefersOneAttemptAndCleansUp proves supervisor-owned invocation.
func TestNativeDecisionPostActionDefersOneAttemptAndCleansUp(t *testing.T) {
	provider := &recordingDecisionEffectProvider{
		descriptor: nativeDecisionEffectDescriptor(),
		result: pluginapi.DecisionEffectResult{
			Outcome: pluginapi.DecisionEffectOutcomeUnknown, ErrorClass: pluginapi.DecisionErrorClassUnavailable,
		},
	}
	prepared := mustPrepareNativeDecisionBindings(t, &recordingDecisionFactProvider{
		descriptor: nativeDecisionFactDescriptor(),
	}, provider, nil)

	work := mustPrepareNativeDecisionPostWork(t, prepared)

	if provider.callCount() != 0 {
		t.Fatal("Prepare() invoked post-action provider")
	}

	executable, ok := work.(effectsupervisor.ExecutableWork)
	if !ok || executable.Validate() != nil {
		t.Fatalf("prepared work = %#v, want valid executable", work)
	}

	result := executable.Execute(t.Context())
	if result.State() != effectsupervisor.StateOutcomeUnknown || provider.callCount() != 1 {
		t.Fatalf("post result/calls = %q/%d", result.State(), provider.callCount())
	}

	executable.Cleanup()
	executable.Cleanup()

	if err := executable.Validate(); !errors.Is(err, effectsupervisor.ErrInvalidWork) {
		t.Fatalf("Validate() after cleanup = %v, want ErrInvalidWork", err)
	}
}

// TestNativeDecisionPostActionRunsOnlyAfterSupervisorFinalization proves the real acceptance boundary.
func TestNativeDecisionPostActionRunsOnlyAfterSupervisorFinalization(t *testing.T) {
	invoked := make(chan struct{}, 1)
	provider := &recordingDecisionEffectProvider{
		descriptor: nativeDecisionEffectDescriptor(), invoked: invoked,
		result: pluginapi.DecisionEffectResult{
			Outcome: pluginapi.DecisionEffectOutcomeUnknown, ErrorClass: pluginapi.DecisionErrorClassUnavailable,
		},
	}
	prepared := mustPrepareNativeDecisionBindings(t, &recordingDecisionFactProvider{
		descriptor: nativeDecisionFactDescriptor(),
	}, provider, nil)
	work := mustPrepareNativeDecisionPostWork(t, prepared)

	observer := &recordingNativeEffectObserver{}
	supervisor := mustNewNativeDecisionSupervisor(t, observer)
	gate := mustNewNativeDecisionGate(t)
	plan := mustNewNativeDecisionPlan(t, gate, work)

	mustAcceptNativeDecisionPlan(t, supervisor, plan)
	assertNativeDecisionInvocationBlocked(t, invoked)

	finalizedResponse := "permit"

	gate.Complete()
	waitNativeDecisionInvocation(t, invoked)
	waitNativeDecisionSupervisorIdle(t, supervisor)
	assertNativeDecisionPostCompletion(t, provider, work, observer, finalizedResponse)
}

// TestNativeDecisionPostActionCleanupDuringExecutionKeepsCapturedRequestStable proves race-safe ownership.
func TestNativeDecisionPostActionCleanupDuringExecutionKeepsCapturedRequestStable(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})

	var releaseOnce sync.Once

	releaseProvider := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseProvider)

	provider := &recordingDecisionEffectProvider{
		descriptor: nativeDecisionEffectDescriptor(),
		result:     pluginapi.DecisionEffectResult{Outcome: pluginapi.DecisionEffectOutcomeSucceeded},
		onExecute: func(context.Context) {
			close(started)
			<-release
		},
	}
	prepared := mustPrepareNativeDecisionBindings(t, &recordingDecisionFactProvider{
		descriptor: nativeDecisionFactDescriptor(),
	}, provider, nil)
	work := mustPrepareNativeDecisionPostWork(t, prepared)

	executable := work.(effectsupervisor.ExecutableWork)
	result := make(chan effectsupervisor.Result, 1)

	go func() { result <- executable.Execute(t.Context()) }()

	<-started

	cleaned := make(chan struct{})

	go func() {
		executable.Cleanup()
		close(cleaned)
	}()

	select {
	case <-cleaned:
	case <-time.After(time.Second):
		t.Fatal("concurrent native work cleanup blocked")
	}

	releaseProvider()

	if got := <-result; got.State() != effectsupervisor.StateSucceeded {
		t.Fatalf("Execute() state = %q, want succeeded", got.State())
	}

	if executable.Validate() == nil || provider.lastEffectRequest().Effect() != "archive" {
		t.Fatal("cleanup did not invalidate work or corrupted the captured request")
	}
}

// TestObservePluginCallContainsObserverPanic proves observation cannot replace call outcomes.
func TestObservePluginCallContainsObserverPanic(t *testing.T) {
	tests := []struct {
		call    func(context.Context) error
		wantErr error
		name    string
	}{
		{name: "successful call", call: func(context.Context) error { return nil }},
		{name: "plugin panic", call: func(context.Context) error { panic("plugin-secret") }, wantErr: ErrPluginPanic},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recovered, err := invokePluginCallWithRecovery(t.Context(), panickingPluginObserver{}, test.call)
			if recovered != nil {
				t.Fatalf("observer panic escaped plugin boundary: %v", recovered)
			}

			if !errors.Is(err, test.wantErr) {
				t.Fatalf("invokePluginCall() error = %v, want %v", err, test.wantErr)
			}

			if err != nil && strings.Contains(err.Error(), "plugin-secret") {
				t.Fatalf("invokePluginCall() exposed plugin panic text: %v", err)
			}
		})
	}
}

type recordingDecisionFactProvider struct {
	descriptor pluginapi.DecisionFactProviderDescriptor
	result     pluginapi.DecisionFactResult
	err        error
	panicValue any
	onCollect  func(context.Context)
	request    pluginapi.DecisionFactRequest
	deadline   time.Time
	calls      int
	mu         sync.Mutex
}

// Descriptor returns the fake provider capability.
func (p *recordingDecisionFactProvider) Descriptor() pluginapi.DecisionFactProviderDescriptor {
	return p.descriptor
}

// Collect records the immutable host request and returns the configured behavior.
func (p *recordingDecisionFactProvider) Collect(
	ctx context.Context,
	request pluginapi.DecisionFactRequest,
) (pluginapi.DecisionFactResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls++
	p.request = request
	p.deadline, _ = ctx.Deadline()

	if p.onCollect != nil {
		p.onCollect(ctx)
	}

	if p.panicValue != nil {
		panic(p.panicValue)
	}

	return p.result, p.err
}

// callCount returns the synchronized fact callback count.
func (p *recordingDecisionFactProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.calls
}

// lastFactCall returns the most recent captured request and deadline.
func (p *recordingDecisionFactProvider) lastFactCall() (pluginapi.DecisionFactRequest, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.request, p.deadline
}

type recordingDecisionEffectProvider struct {
	descriptor pluginapi.DecisionEffectProviderDescriptor
	result     pluginapi.DecisionEffectResult
	err        error
	panicValue any
	onExecute  func(context.Context)
	invoked    chan<- struct{}
	request    pluginapi.DecisionEffectRequest
	calls      int
	mu         sync.Mutex
}

// Descriptor returns the fake effect capability.
func (p *recordingDecisionEffectProvider) Descriptor() pluginapi.DecisionEffectProviderDescriptor {
	return p.descriptor
}

// Execute records the selected effect request and returns the configured behavior.
func (p *recordingDecisionEffectProvider) Execute(
	ctx context.Context,
	request pluginapi.DecisionEffectRequest,
) (pluginapi.DecisionEffectResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls++
	p.request = request

	if p.invoked != nil {
		select {
		case p.invoked <- struct{}{}:
		default:
		}
	}

	if p.onExecute != nil {
		p.onExecute(ctx)
	}

	if p.panicValue != nil {
		panic(p.panicValue)
	}

	return p.result, p.err
}

// callCount returns the synchronized effect callback count.
func (p *recordingDecisionEffectProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.calls
}

// lastEffectRequest returns the most recent captured selected-effect request.
func (p *recordingDecisionEffectProvider) lastEffectRequest() pluginapi.DecisionEffectRequest {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.request
}

type recordingPluginObserver struct {
	entries []CallRecord
	mu      sync.Mutex
}

type recordingNativeEffectObserver struct {
	events []effectsupervisor.Event
	mu     sync.Mutex
}

// Observe records one bounded supervisor transition.
func (o *recordingNativeEffectObserver) Observe(_ context.Context, event effectsupervisor.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.events = append(o.events, event)
}

// saw reports whether one exact state and phase were observed.
func (o *recordingNativeEffectObserver) saw(
	state effectsupervisor.State,
	phase effectsupervisor.Phase,
) bool {
	for _, event := range o.eventsCopy() {
		if event.State == state && event.Phase == phase {
			return true
		}
	}

	return false
}

// eventsCopy returns a synchronized event snapshot.
func (o *recordingNativeEffectObserver) eventsCopy() []effectsupervisor.Event {
	o.mu.Lock()
	defer o.mu.Unlock()

	return append([]effectsupervisor.Event(nil), o.events...)
}

type panickingPluginObserver struct{}

// ObservePluginCall simulates a broken operational observer.
func (panickingPluginObserver) ObservePluginCall(CallRecord) {
	panic("observer-secret")
}

// invokePluginCallWithRecovery captures any panic escaping the shared native call boundary.
func invokePluginCallWithRecovery(
	ctx context.Context,
	observer Observer,
	call func(context.Context) error,
) (recovered any, err error) {
	defer func() { recovered = recover() }()

	err = invokePluginCall(ctx, observer, invokeSpec{
		moduleName: "observer_test", componentName: "callback",
		extensionPoint: "decision_effect_provider", method: "Execute",
	}, call)

	return nil, err
}

// mustPrepareNativeDecisionPostWork prepares selected work without invoking the provider.
func mustPrepareNativeDecisionPostWork(t *testing.T, prepared DecisionBindings) effectsupervisor.Work {
	t.Helper()

	postProvider := prepared.PostActions()[testNativeDecisionEffectProvider]

	work, err := postProvider.Prepare(
		t.Context(),
		nativeDecisionEffectExecution(t, testNativeDecisionPostEffectID, 2),
	)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	return work
}

// mustNewNativeDecisionSupervisor starts a bounded executable-work supervisor.
func mustNewNativeDecisionSupervisor(
	t *testing.T,
	observer effectsupervisor.Observer,
) *effectsupervisor.Supervisor {
	t.Helper()

	supervisor, err := effectsupervisor.New(effectsupervisor.Config{
		Lifetime: context.Background(), Observer: observer, Capacity: 1, Workers: 1,
	}, effectsupervisor.ProviderBinding{
		Name: testNativeDecisionEffectProvider, Provider: effectsupervisor.NewExecutableProvider(),
	})
	if err != nil {
		t.Fatalf("effectsupervisor.New() error = %v", err)
	}

	t.Cleanup(func() { shutdownNativeDecisionSupervisor(t, supervisor) })

	return supervisor
}

// mustNewNativeDecisionGate creates the response finalization boundary.
func mustNewNativeDecisionGate(t *testing.T) *effectsupervisor.Gate {
	t.Helper()

	gate, err := effectsupervisor.NewGate(effectsupervisor.BoundaryHTTPCommit)
	if err != nil {
		t.Fatalf("NewGate() error = %v", err)
	}

	return gate
}

// mustNewNativeDecisionPlan constructs one bounded accepted post-action plan.
func mustNewNativeDecisionPlan(
	t *testing.T,
	gate effectsupervisor.FinalizationGate,
	work effectsupervisor.Work,
) effectsupervisor.Plan {
	t.Helper()

	plan, err := effectsupervisor.NewPlan(effectsupervisor.PlanInput{
		Gate: gate, Work: work, DecisionID: "decision-native-supervisor", Target: "mail/filter",
		Provider: testNativeDecisionEffectProvider, DeadlineBudget: time.Second, EffectOrdinal: 2,
		Observability: effectsupervisor.ObservabilityMetadata{RuntimeGeneration: 1, Source: "native"},
	})
	if err != nil {
		t.Fatalf("NewPlan() error = %v", err)
	}

	return plan
}

// mustAcceptNativeDecisionPlan requires synchronous supervisor acceptance.
func mustAcceptNativeDecisionPlan(
	t *testing.T,
	supervisor *effectsupervisor.Supervisor,
	plan effectsupervisor.Plan,
) {
	t.Helper()

	if _, err := supervisor.Accept(t.Context(), plan); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
}

// assertNativeDecisionInvocationBlocked proves accepted work waits for response finalization.
func assertNativeDecisionInvocationBlocked(t *testing.T, invoked <-chan struct{}) {
	t.Helper()

	select {
	case <-invoked:
		t.Fatal("accepted native post-action ran before finalization")
	case <-time.After(20 * time.Millisecond):
	}
}

// waitNativeDecisionInvocation waits for provider execution after response finalization.
func waitNativeDecisionInvocation(t *testing.T, invoked <-chan struct{}) {
	t.Helper()

	select {
	case <-invoked:
	case <-time.After(time.Second):
		t.Fatal("native post-action did not run after finalization")
	}
}

// assertNativeDecisionPostCompletion verifies response isolation, cleanup, and late telemetry.
func assertNativeDecisionPostCompletion(
	t *testing.T,
	provider *recordingDecisionEffectProvider,
	work effectsupervisor.Work,
	observer *recordingNativeEffectObserver,
	finalizedResponse string,
) {
	t.Helper()

	if finalizedResponse != "permit" || provider.callCount() != 1 {
		t.Fatalf("late execution mutated response or call count: %q/%d", finalizedResponse, provider.callCount())
	}

	executable := work.(effectsupervisor.ExecutableWork)
	if !errors.Is(executable.Validate(), effectsupervisor.ErrInvalidWork) {
		t.Fatal("supervisor did not clean up accepted native work")
	}

	if !observer.saw(effectsupervisor.StateOutcomeUnknown, effectsupervisor.PhaseExecution) {
		t.Fatalf("supervisor events = %#v, want late execution outcome_unknown", observer.eventsCopy())
	}
}

// waitNativeDecisionSupervisorIdle waits for accepted native work and cleanup to finish.
func waitNativeDecisionSupervisorIdle(t *testing.T, supervisor *effectsupervisor.Supervisor) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := supervisor.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle() error = %v", err)
	}
}

// shutdownNativeDecisionSupervisor stops test workers within a bounded cleanup budget.
func shutdownNativeDecisionSupervisor(t *testing.T, supervisor *effectsupervisor.Supervisor) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := supervisor.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

// ObservePluginCall records one bounded native callback event.
func (o *recordingPluginObserver) ObservePluginCall(record CallRecord) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.entries = append(o.entries, record)
}

// records returns a detached observation snapshot.
func (o *recordingPluginObserver) records() []CallRecord {
	o.mu.Lock()
	defer o.mu.Unlock()

	return append([]CallRecord(nil), o.entries...)
}

// nativeDecisionGenerationBindings constructs captured generic and legacy native components.
func nativeDecisionGenerationBindings(
	factProvider pluginapi.DecisionFactProvider,
	effectProvider pluginapi.DecisionEffectProvider,
) *GenerationBindings {
	return &GenerationBindings{modules: []GenerationModuleBinding{{
		moduleName: testNativeDecisionModule,
		components: []pluginregistry.Component{
			{
				Value: factProvider, DecisionFactProviderDescriptor: factProvider.Descriptor(),
				ModuleName: testNativeDecisionModule, LocalName: testNativeDecisionFactComponent,
				Kind: pluginregistry.ComponentKindDecisionFactProvider, Origin: pluginregistry.ComponentOriginNative,
			},
			{
				Value: effectProvider, DecisionEffectProviderDescriptor: effectProvider.Descriptor(),
				ModuleName: testNativeDecisionModule, LocalName: testNativeDecisionEffectComponent,
				Kind: pluginregistry.ComponentKindDecisionEffectProvider, Origin: pluginregistry.ComponentOriginNative,
			},
			{
				Value: &struct{}{}, ModuleName: testNativeDecisionModule, LocalName: "legacy_subject",
				Kind: pluginregistry.ComponentKindSubjectSource, Origin: pluginregistry.ComponentOriginNative,
			},
		},
	}}}
}

// nativeDecisionFactDescriptor returns one target-aware public fact capability.
func nativeDecisionFactDescriptor() pluginapi.DecisionFactProviderDescriptor {
	return pluginapi.DecisionFactProviderDescriptor{
		Namespace: testNativeDecisionNamespace,
		Name:      testNativeDecisionFactComponent,
		Timeout:   100 * time.Millisecond,
		Targets: []pluginapi.DecisionTargetSelector{{
			Namespace: testNativeDecisionNamespace, Action: "filter",
		}},
		Outputs: []pluginapi.DecisionFactOutputDescriptor{{
			Name: "risk.score", Category: pluginapi.DecisionFactCategoryEnvironment,
			Kind: pluginapi.DecisionValueKindString, MaxLength: 16,
		}},
	}
}

// nativeDecisionEffectDescriptor returns synchronous and post-action public effects.
func nativeDecisionEffectDescriptor() pluginapi.DecisionEffectProviderDescriptor {
	parameters := []pluginapi.DecisionEffectParameterDescriptor{{
		Name: "level", Kind: pluginapi.DecisionValueKindString, MaxLength: 16, Required: true,
	}}

	return pluginapi.DecisionEffectProviderDescriptor{
		Namespace: testNativeDecisionNamespace,
		Name:      testNativeDecisionEffectComponent,
		Effects: []pluginapi.DecisionEffectDescriptor{
			{
				Name: "notify", Execution: pluginapi.DecisionEffectExecutionHostSync,
				Targets:    []pluginapi.DecisionTargetSelector{{Namespace: "mail", Action: "filter"}},
				Parameters: parameters,
			},
			{
				Name: "archive", Execution: pluginapi.DecisionEffectExecutionHostPostAction,
				Targets:    []pluginapi.DecisionTargetSelector{{Namespace: "mail", Action: "filter"}},
				Parameters: parameters,
			},
		},
	}
}

// nativeDecisionFactDefinition constructs the configured internal fact provider schedule.
func nativeDecisionFactDefinition(t *testing.T) policyregistry.ProviderDefinition {
	t.Helper()

	return nativeDecisionFactDefinitionWithID(t, testNativeDecisionFactProviderID)
}

// nativeDecisionFactDefinitionWithID constructs a schedule under one provider identity.
func nativeDecisionFactDefinitionWithID(t *testing.T, id string) policyregistry.ProviderDefinition {
	t.Helper()

	output, err := policyregistry.NewProviderFactOutput(policyregistry.ProviderFactOutputInput{
		ID: testNativeDecisionFactID, Category: decision.FactCategoryEnvironment,
		Kind: decision.ValueKindString, MaxLength: 16,
	})
	if err != nil {
		t.Fatalf("NewProviderFactOutput() error = %v", err)
	}

	definition, err := policyregistry.NewProviderDefinition(policyregistry.ProviderDefinitionInput{
		ID: id, Targets: []decision.Target{nativeDecisionTarget(t)}, Outputs: []policyregistry.ProviderFactOutput{output},
		Failure: policyregistry.ProviderFailureIndeterminate, Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	return definition
}

// nativeDecisionEffectProviderDefinition constructs the configured effect-provider binding.
func nativeDecisionEffectProviderDefinition(t *testing.T) policyregistry.ProviderDefinition {
	t.Helper()

	definition, err := policyregistry.NewProviderDefinition(policyregistry.ProviderDefinitionInput{
		ID: testNativeDecisionEffectProvider, Targets: []decision.Target{nativeDecisionTarget(t)},
		Executions: []policyregistry.ExecutionClass{
			policyregistry.ExecutionHostSync, policyregistry.ExecutionHostPostAction,
		},
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	return definition
}

// nativeDecisionScheduledEffectProviderDefinition constructs an invalid effect owner carrying a fact schedule.
func nativeDecisionScheduledEffectProviderDefinition(t *testing.T) policyregistry.ProviderDefinition {
	t.Helper()

	definition, err := policyregistry.NewProviderDefinition(policyregistry.ProviderDefinitionInput{
		ID: testNativeDecisionEffectProvider, Targets: []decision.Target{nativeDecisionTarget(t)},
		Executions: []policyregistry.ExecutionClass{
			policyregistry.ExecutionHostSync, policyregistry.ExecutionHostPostAction,
		},
		Failure: policyregistry.ProviderFailureIndeterminate, Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	return definition
}

// nativeDecisionEffectDefinitions constructs the exact configured selected-effect catalog entries.
func nativeDecisionEffectDefinitions(t *testing.T) []policyregistry.EffectDefinition {
	t.Helper()

	return []policyregistry.EffectDefinition{
		nativeDecisionEffectDefinition(t, testNativeDecisionSyncEffectID, policyregistry.ExecutionHostSync),
		nativeDecisionEffectDefinition(t, testNativeDecisionPostEffectID, policyregistry.ExecutionHostPostAction),
	}
}

// nativeDecisionEffectDefinition constructs one typed selected effect.
func nativeDecisionEffectDefinition(
	t *testing.T,
	id string,
	execution policyregistry.ExecutionClass,
) policyregistry.EffectDefinition {
	t.Helper()

	parameter, err := policyregistry.NewParameterSchema(policyregistry.ParameterSchemaInput{
		Name: "level", Kind: decision.ValueKindString, MaxLength: 16, Required: true,
	})
	if err != nil {
		t.Fatalf("NewParameterSchema() error = %v", err)
	}

	definition, err := policyregistry.NewEffectDefinition(policyregistry.EffectDefinitionInput{
		ID: id, Provider: testNativeDecisionEffectProvider, Targets: []decision.Target{nativeDecisionTarget(t)},
		Parameters: []policyregistry.ParameterSchema{parameter}, Kind: policyregistry.EffectKindObligation,
		Execution: execution,
	})
	if err != nil {
		t.Fatalf("NewEffectDefinition() error = %v", err)
	}

	return definition
}

// mustPrepareNativeDecisionBindings prepares the full fake configured selection.
func mustPrepareNativeDecisionBindings(
	t *testing.T,
	factProvider pluginapi.DecisionFactProvider,
	effectProvider pluginapi.DecisionEffectProvider,
	observer Observer,
) DecisionBindings {
	t.Helper()

	prepared, err := nativeDecisionGenerationBindings(factProvider, effectProvider).PrepareDecisionBindings(
		t.Context(),
		DecisionBindingInput{
			Observer: observer,
			FactProviders: []DecisionFactBindingInput{{
				Definition: nativeDecisionFactDefinition(t), ModuleName: testNativeDecisionModule,
				ComponentName: testNativeDecisionFactComponent,
			}},
			EffectProviders: []DecisionEffectBindingInput{{
				Definition: nativeDecisionEffectProviderDefinition(t), Effects: nativeDecisionEffectDefinitions(t),
				ModuleName: testNativeDecisionModule, ComponentName: testNativeDecisionEffectComponent,
			}},
		},
	)
	if err != nil {
		t.Fatalf("PrepareDecisionBindings() error = %v", err)
	}

	return prepared
}

// nativeDecisionFactInput constructs one immutable provider input.
func nativeDecisionFactInput(t *testing.T, target decision.Target) policyruntime.FactProviderInput {
	t.Helper()

	input, err := policyruntime.NewFactProviderInput(
		nativeDecisionFacts(t), target, nativeDecisionCaller(t), "policy.facts.collect",
	)
	if err != nil {
		t.Fatalf("NewFactProviderInput() error = %v", err)
	}

	return input
}

// nativeDecisionCollisionFactInput constructs input that already contains the provider-owned output.
func nativeDecisionCollisionFactInput(t *testing.T) policyruntime.FactProviderInput {
	t.Helper()

	provenance, err := decision.NewProvenance(
		decision.FactSourcePlugin,
		testNativeDecisionModule,
		testNativeDecisionFactProviderID,
	)
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	fact, err := decision.NewFact(
		testNativeDecisionFactID,
		decision.FactCategoryEnvironment,
		nativeDecisionStringValue(t, "existing"),
		provenance,
	)
	if err != nil {
		t.Fatalf("NewFact() error = %v", err)
	}

	facts, err := decision.NewFactSet([]decision.Fact{fact})
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	input, err := policyruntime.NewFactProviderInput(
		facts,
		nativeDecisionTarget(t),
		nativeDecisionCaller(t),
		"policy.facts.collect",
	)
	if err != nil {
		t.Fatalf("NewFactProviderInput() error = %v", err)
	}

	return input
}

// nativeDecisionEffectExecution constructs one immutable selected effect invocation.
func nativeDecisionEffectExecution(t *testing.T, effectID string, ordinal uint32) policyruntime.EffectExecution {
	t.Helper()

	return nativeDecisionEffectExecutionWith(
		t,
		effectID,
		ordinal,
		nativeDecisionTarget(t),
		map[string]decision.Value{"level": nativeDecisionStringValue(t, "security")},
	)
}

// nativeDecisionEffectExecutionWith constructs one selected effect invocation from explicit authority inputs.
func nativeDecisionEffectExecutionWith(
	t *testing.T,
	effectID string,
	ordinal uint32,
	target decision.Target,
	parameterValues map[string]decision.Value,
) policyruntime.EffectExecution {
	t.Helper()

	parameters, err := decision.NewValueMap(parameterValues)
	if err != nil {
		t.Fatalf("NewValueMap() error = %v", err)
	}

	execution, err := policyruntime.NewEffectExecution(policyruntime.EffectExecutionInput{
		Facts: nativeDecisionFacts(t), Caller: nativeDecisionCaller(t), Parameters: parameters,
		Target: target, EffectID: effectID, DecisionID: "decision-native-1",
		Provider: testNativeDecisionEffectProvider, Generation: 1, Ordinal: ordinal,
	})
	if err != nil {
		t.Fatalf("NewEffectExecution() error = %v", err)
	}

	return execution
}

// nativeDecisionFacts constructs one visible caller fact.
func nativeDecisionFacts(t *testing.T) decision.FactSet {
	t.Helper()

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "client", "resource")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	fact, err := decision.NewFact(
		"resource.id", decision.FactCategoryResource, nativeDecisionStringValue(t, "message-1"), provenance,
	)
	if err != nil {
		t.Fatalf("NewFact() error = %v", err)
	}

	facts, err := decision.NewFactSet([]decision.Fact{fact})
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return facts
}

// nativeDecisionCaller constructs trusted caller evidence for the public redacted view.
func nativeDecisionCaller(t *testing.T) decision.CallerContext {
	t.Helper()

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: "policy-client", ClientID: "client-1", Scopes: []string{"policy.evaluate"},
		AuthenticationKind: "basic", TransportKind: "http",
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	return caller
}

// nativeDecisionTarget constructs the configured exact target.
func nativeDecisionTarget(t *testing.T) decision.Target {
	t.Helper()

	return mustNativeDecisionTarget(t, "mail", "filter")
}

// mustNativeDecisionTarget constructs one exact target fixture.
func mustNativeDecisionTarget(t *testing.T, namespace string, action string) decision.Target {
	t.Helper()

	target, err := decision.NewTarget(namespace, action)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return target
}

// nativeDecisionStringValue constructs one strict internal string value.
func nativeDecisionStringValue(t *testing.T, input string) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return value
}

// nativeDecisionBooleanValue constructs one strict internal boolean value.
func nativeDecisionBooleanValue(t *testing.T, input bool) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{Boolean: &input})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return value
}

// mustPluginDecisionStringValue constructs one strict public string value.
func mustPluginDecisionStringValue(t *testing.T, input string) pluginapi.DecisionValue {
	t.Helper()

	return mustPluginDecisionValue(t, pluginapi.DecisionValueInput{String: pointerTo(input)})
}

// mustPluginDecisionBooleanValue constructs one strict public boolean value.
func mustPluginDecisionBooleanValue(t *testing.T, input bool) pluginapi.DecisionValue {
	t.Helper()

	return mustPluginDecisionValue(t, pluginapi.DecisionValueInput{Boolean: pointerTo(input)})
}

// mustPluginDecisionValue requires a valid strict public one-of value.
func mustPluginDecisionValue(t *testing.T, input pluginapi.DecisionValueInput) pluginapi.DecisionValue {
	t.Helper()

	value, err := pluginapi.NewDecisionValue(input)
	if err != nil {
		t.Fatalf("NewDecisionValue() error = %v", err)
	}

	return value
}

// pointerTo returns a stable pointer for strict one-of constructor fixtures.
func pointerTo[T any](value T) *T {
	return &value
}

// containsSecret checks that bounded runtime errors do not echo plugin-controlled panic text.
func containsSecret(value string) bool {
	return strings.Contains(value, "secret-value")
}
