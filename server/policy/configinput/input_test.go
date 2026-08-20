// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

type testAcceptanceCapability struct{}

const crossNamespacePolicyFixture = `policy:
  namespaces:
    shared:
      policy_sets:
        deny-risk:
          visibility: exported
          export_contract:
            required_facts:
              - attribute: environment.network.risk
                type: string
            compatible_checkpoints: [final_decision]
            allowed_decisions: [deny]
            allowed_effects: []
          rules:
            - name: deny-risk
              checkpoint: final_decision
              if:
                attribute: environment.network.risk
                in: [high, critical]
              then:
                decision: deny
    dkim2:
      schema_contributions:
        static:
          sign-message-instance:
            versions:
              v1:
                facts:
                  - attribute: environment.network.risk
                    category: environment
                    type: string
                    allowed_sources: [caller]
      policy_sets:
        default:
          rules: []
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      default_policy: dkim2/default
      no_match: not_applicable
      timeouts:
        evaluation: 2s
        provider_default: 500ms
      plans:
        final_decision:
          policy_sets: [shared/deny-risk, dkim2/default]
`

const exactGenericTargetFixture = `policy:
  api:
    clients:
      - principal: dkim2-client
        targets:
          - namespace: dkim2
            actions: [sign-message-instance]
  namespaces:
    dkim2:
      schema_contributions:
        static:
          sign-message-instance:
            versions:
              v1:
                facts: []
      policy_sets:
        default:
          rules: []
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      default_policy: dkim2/default
      no_match: deny
      timeouts:
        evaluation: 2s
        provider_default: 500ms
      plans:
        final_decision:
          policy_sets: [dkim2/default]
`

// Accept proves that the standalone catalog harness receives host capability by injection.
func (testAcceptanceCapability) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

func TestUnifiedPolicyInputEmptyConfigProvidesOnlyBuiltinAuthnDefaults(t *testing.T) {
	input, err := Normalize(context.Background(), policyconfig.Document{})
	requireNoError(t, err)

	if len(input.Definitions) != 1 {
		t.Fatalf("definition contributions = %d, want builtin contribution only", len(input.Definitions))
	}

	if owner := input.Definitions[0].Ownership().Owner(); owner != "builtin.authn" {
		t.Fatalf("definition owner = %q, want builtin.authn", owner)
	}

	sets := input.Definitions[0].PolicySets()
	if len(sets) != 1 || sets[0].ID().String() != registry.BuiltinStandardAuthPolicySet {
		t.Fatalf("builtin sets = %v, want only %s", policySetIDs(sets), registry.BuiltinStandardAuthPolicySet)
	}

	wantSchemas := map[string]bool{
		"authn/authenticate/v1":    false,
		"authn/lookup_identity/v1": false,
		"authn/list_accounts/v1":   false,
	}
	if len(input.Activations) != len(wantSchemas) {
		t.Fatalf("activations = %d, want %d", len(input.Activations), len(wantSchemas))
	}

	for _, activation := range input.Activations {
		wantSchemas[activation.Schema().String()] = true
		if got := activation.DefaultPolicySet().String(); got != registry.BuiltinStandardAuthPolicySet {
			t.Fatalf("%s default = %q, want %q", activation.Target().String(), got, registry.BuiltinStandardAuthPolicySet)
		}

		if activation.NoMatch() != registry.NoMatchUnset {
			t.Fatalf("%s no_match = %q, want unset", activation.Target().String(), activation.NoMatch())
		}
	}

	for schema, activated := range wantSchemas {
		if !activated {
			t.Fatalf("builtin schema %s was not activated", schema)
		}
	}

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	if catalog.Len() != 3 {
		t.Fatalf("compiled targets = %d, want 3", catalog.Len())
	}
}

func TestUnifiedPolicyInputCompileUsesOneNormalizedPolicySnapshot(t *testing.T) {
	input, err := Normalize(context.Background(), policyconfig.Document{})
	requireNoError(t, err)

	input.Activations = nil
	input.AdmissionProfiles = nil

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	if catalog.Len() != len(builtinAuthnTargets) {
		t.Fatalf("compiled targets = %d, want %d rebuilt from policy snapshot", catalog.Len(), len(builtinAuthnTargets))
	}
}

func TestUnifiedPolicyInputConfiguredAuthnUsesQualifiedBuiltinDefault(t *testing.T) {
	document := decodePolicy(t, `policy:
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      mode: observe
`)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	activation := findActivation(t, input, "authn/authenticate")
	if activation.DefaultPolicySet().String() != registry.BuiltinStandardAuthPolicySet {
		t.Fatalf("default policy = %q, want %q", activation.DefaultPolicySet().String(), registry.BuiltinStandardAuthPolicySet)
	}

	if activation.AuthorityMode() != registry.AuthorityModeObserve {
		t.Fatalf("authority mode = %q, want observe", activation.AuthorityMode())
	}

	_, err = input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)
}

func TestUnifiedPolicyInputLeavesUnactivatedGenericDefinitionsInert(t *testing.T) {
	document := decodePolicy(t, `policy:
  namespaces:
    dkim2:
      schema_contributions:
        static:
          sign-message-instance:
            versions:
              v1:
                facts: []
`)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	if len(input.Activations) != len(builtinAuthnTargets) {
		t.Fatalf("activations = %d, want only %d builtin authn targets", len(input.Activations), len(builtinAuthnTargets))
	}

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	if catalog.Len() != len(builtinAuthnTargets) {
		t.Fatalf("compiled targets = %d, want generic definition inert", catalog.Len())
	}
}

func TestUnifiedPolicyInputNormalizesExactGenericTargetAndAdmission(t *testing.T) {
	document := decodePolicy(t, exactGenericTargetFixture)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	activation := findActivation(t, input, "dkim2/sign-message-instance")
	if got := activation.Schema().String(); got != "dkim2/sign-message-instance/v1" {
		t.Fatalf("schema = %q, want exact v1", got)
	}

	if activation.NoMatch() != registry.NoMatchDeny {
		t.Fatalf("no_match = %q, want deny", activation.NoMatch())
	}

	if len(input.Admissions) != 1 {
		t.Fatalf("admission references = %d, want 1", len(input.Admissions))
	}

	if got := input.Admissions[0].Schema().String(); got != activation.Schema().String() {
		t.Fatalf("admission schema = %q, want %q", got, activation.Schema().String())
	}

	if len(input.Policy.API.Clients) != 1 {
		t.Fatal("typed auxiliary API/client configuration was discarded")
	}

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	if catalog.Len() != 4 {
		t.Fatalf("compiled targets = %d, want builtin three plus generic target", catalog.Len())
	}
}

func TestUnifiedPolicyInputRejectsUndeclaredExactSchema(t *testing.T) {
	document := decodePolicy(t, `policy:
  namespaces:
    dkim2:
      policy_sets:
        default:
          rules: []
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      default_policy: dkim2/default
      no_match: deny
      timeouts:
        evaluation: 2s
        provider_default: 500ms
      plans:
        final_decision:
          policy_sets: [dkim2/default]
`)

	_, err := Normalize(context.Background(), document)

	var pathError *PathError

	if !errors.As(err, &pathError) {
		t.Fatalf("Normalize() error = %v, want path error", err)
	}

	if pathError.Path != "policy.targets[0].schema" {
		t.Fatalf("Normalize() path = %q, want policy.targets[0].schema", pathError.Path)
	}
}

func TestUnifiedPolicyInputRejectsCrossTargetDefault(t *testing.T) {
	document := decodePolicy(t, `policy:
  namespaces:
    dkim2:
      schema_contributions:
        static:
          sign-message-instance:
            versions:
              v1:
                facts: []
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      default_policy: authn/standard_auth
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision:
          policy_sets: []
`)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	_, err = input.Compile(context.Background(), testAcceptanceCapability{})
	if err == nil {
		t.Fatal("cross-target authn default compiled for a generic target")
	}

	if !strings.Contains(err.Error(), "policy.targets[0].default_policy") {
		t.Fatalf("Compile() error = %q, want exact default-policy path", err)
	}
}

func TestUnifiedPolicyInputNormalizesCrossNamespaceExportBinding(t *testing.T) {
	document := decodePolicy(t, crossNamespacePolicyFixture)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	activation := findActivation(t, input, "dkim2/sign-message-instance")

	bindings := activation.PolicySetBindings()
	if len(bindings) != 2 {
		t.Fatalf("policy-set bindings = %d, want 2", len(bindings))
	}

	if got := bindings[0].Set().String(); got != "shared/deny-risk" {
		t.Fatalf("first binding = %q, want shared/deny-risk", got)
	}

	if !bindings[0].Contract().Complete() {
		t.Fatal("cross-namespace binding did not retain the exact export contract")
	}

	if bindings[1].Contract().Complete() {
		t.Fatal("same-namespace binding unexpectedly carries an import contract")
	}

	set := findPolicySet(t, input, "shared/deny-risk")

	contract, ok := set.ExportContract()
	if !ok || !contract.Equal(bindings[0].Contract()) {
		t.Fatal("binding contract differs from the exported source contract")
	}

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	if catalog.Len() != 4 {
		t.Fatalf("compiled targets = %d, want builtin three plus configured target", catalog.Len())
	}
}

func TestUnifiedPolicyInputNormalizesProviderFailureAndEffectExecution(t *testing.T) {
	document := decodePolicy(t, `policy:
  namespaces:
    dkim2:
      schema_contributions:
        static:
          sign-message-instance:
            versions:
              v1:
                facts: []
      providers:
        dispatch:
          kind: native
          targets:
            - action: sign-message-instance
          executions: [host_sync]
          failure: continue
          timeout: 200ms
      effects:
        notify:
          kind: obligation
          provider: dkim2/dispatch
          targets:
            - action: sign-message-instance
          execution: host_sync
      policy_sets:
        default:
          rules: []
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      default_policy: dkim2/default
      no_match: deny
      timeouts:
        evaluation: 2s
        provider_default: 500ms
      plans:
        final_decision:
          policy_sets: [dkim2/default]
`)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	provider, effect := findProviderAndEffect(t, input, "dkim2/dispatch", "dkim2/notify")
	if provider.Failure() != registry.ProviderFailureContinue {
		t.Fatalf("provider failure = %q, want continue", provider.Failure())
	}

	if effect.Execution() != registry.ExecutionHostSync || effect.Provider() != provider.ID() {
		t.Fatalf("effect binding = %q/%q, want host_sync/%q", effect.Execution(), effect.Provider(), provider.ID())
	}

	if len(input.Policy.Namespaces["dkim2"].Providers) != 1 || len(input.Policy.Namespaces["dkim2"].Effects) != 1 {
		t.Fatal("typed provider/effect auxiliary configuration was discarded")
	}
}

func TestUnifiedPolicyInputAppliesTargetProviderDefaultTimeout(t *testing.T) {
	document := decodePolicy(t, `policy:
  namespaces:
    dkim2:
      schema_contributions:
        static:
          sign-message-instance:
            versions:
              v1:
                facts: []
      providers:
        risk:
          kind: native
          targets: [{action: sign-message-instance}]
          executions: [host_sync]
          failure: indeterminate
      domain_plans:
        default:
          checkpoints:
            final_decision:
              providers:
                - name: risk
                  use: dkim2/risk
      policy_sets:
        default:
          rules: []
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      domain_plan: dkim2/default
      default_policy: dkim2/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision:
          policy_sets: [dkim2/default]
`)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	provider, _ := findProviderAndEffectOptional(input, "dkim2/risk", "")
	if provider.Timeout() != 500*time.Millisecond {
		t.Fatalf("provider timeout = %s, want target default 500ms", provider.Timeout())
	}

	_, err = input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)
}

// decodePolicy decodes one standalone YAML fixture through the new-root contract.
func decodePolicy(t *testing.T, source string) policyconfig.Document {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(source))
	requireNoError(t, err)

	return document
}

// findActivation resolves one normalized target activation by canonical identity.
func findActivation(t *testing.T, input UnifiedPolicyInput, target string) registry.TargetActivation {
	t.Helper()

	for _, activation := range input.Activations {
		if activation.Target().String() == target {
			return activation
		}
	}

	t.Fatalf("target activation %s not found", target)

	return registry.TargetActivation{}
}

// findPolicySet resolves one normalized policy-set definition by canonical identity.
func findPolicySet(t *testing.T, input UnifiedPolicyInput, identity string) registry.PolicySetDefinition {
	t.Helper()

	for _, contribution := range input.Definitions {
		for _, set := range contribution.PolicySets() {
			if set.ID().String() == identity {
				return set
			}
		}
	}

	t.Fatalf("policy set %s not found", identity)

	return registry.PolicySetDefinition{}
}

// findProviderAndEffect resolves exact normalized provider/effect descriptors.
func findProviderAndEffect(
	t *testing.T,
	input UnifiedPolicyInput,
	providerID string,
	effectID string,
) (registry.ProviderDefinition, registry.EffectDefinition) {
	t.Helper()

	provider, effect := findProviderAndEffectOptional(input, providerID, effectID)

	if provider.ID() == "" || effect.ID() == "" {
		t.Fatalf("normalized provider/effect %s/%s not found", providerID, effectID)
	}

	return provider, effect
}

// findProviderAndEffectOptional resolves either or both normalized descriptors.
func findProviderAndEffectOptional(
	input UnifiedPolicyInput,
	providerID string,
	effectID string,
) (registry.ProviderDefinition, registry.EffectDefinition) {
	var (
		provider registry.ProviderDefinition
		effect   registry.EffectDefinition
	)

	for _, contribution := range input.Definitions {
		for _, candidate := range contribution.Providers() {
			if candidate.ID() == providerID {
				provider = candidate
			}
		}

		for _, candidate := range contribution.Effects() {
			if candidate.ID() == effectID {
				effect = candidate
			}
		}
	}

	return provider, effect
}

// policySetIDs returns stable diagnostic identities for test failures.
func policySetIDs(sets []registry.PolicySetDefinition) []string {
	identities := make([]string, 0, len(sets))
	for _, set := range sets {
		identities = append(identities, set.ID().String())
	}

	return identities
}

// requireNoError fails one focused test on an unexpected error.
func requireNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
