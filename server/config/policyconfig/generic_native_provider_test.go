// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"strings"
	"testing"
)

var invalidGenericNativeProviders = []policyValidationPathCase{
	{
		name: "missing module",
		source: `
          kind: native
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.module",
	},
	{
		name: "noncanonical module",
		source: `
          kind: native
          module: Reputation.Provider
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.module",
	},
	{
		name: "script path",
		source: `
          kind: native
          module: reputation
          script_path: /etc/nauthilus/plugins/reputation.so
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.script_path",
	},
	{
		name: "foreign native authority",
		source: `
          kind: native
          module: reputation
          produced_facts: [plugin.foreign.score]
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.produced_facts[0]",
	},
	{
		name: "foreign source",
		source: `
          kind: native
          module: reputation
          produced_facts: [lua.reputation.score]
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.produced_facts[0]",
	},
	{
		name: "duplicate output",
		source: `
          kind: native
          module: reputation
          produced_facts: [plugin.reputation.score, plugin.reputation.score]
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.produced_facts[1]",
	},
}

func TestGenericNativeProviderOwnsPluginAuthorityBoundConfiguration(t *testing.T) {
	document := decodeGenericNativeProvider(t, `
          kind: native
          module: reputation
          produced_facts: [plugin.reputation.score]
          failure: continue
          timeout: 100ms
`)

	requireNoError(t, Validate(document))

	provider := document.Policy.Namespaces["dkim2"].Providers["risk"]
	requireEqual(t, ProviderKindNative, provider.Kind)
	requireEqual(t, "dkim2/plugin.reputation.risk", provider.CanonicalID("dkim2", "risk"))
}

func TestGenericNativeFactProviderDoesNotGainImplicitHostExecution(t *testing.T) {
	document := decodeGenericNativeProvider(t, `
          kind: native
          module: reputation
          produced_facts: [plugin.reputation.score]
          failure: indeterminate
          timeout: 100ms
`)

	normalized := Normalize(document)
	provider := normalized.Policy.Namespaces["dkim2"].Providers["risk"]

	requireNoError(t, Validate(normalized))

	if len(provider.Executions) != 0 {
		t.Fatalf("fact-only native provider gained implicit executions: %v", provider.Executions)
	}
}

func TestGenericNativeProviderRejectsInvalidBindingConfiguration(t *testing.T) {
	for _, test := range invalidGenericNativeProviders {
		t.Run(test.name, func(t *testing.T) {
			document := decodeGenericNativeProvider(t, test.source)

			err := Validate(document)

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, test.path, pathError.Path)
		})
	}
}

func TestGenericNativeProviderRejectsOversizedDerivedIdentity(t *testing.T) {
	namespace := strings.Repeat("n", 64)
	name := strings.Repeat("r", 63)
	document := Document{Policy: PolicyConfig{Namespaces: map[string]NamespaceConfig{
		namespace: {
			Providers: map[string]ProviderConfig{
				name: {
					Kind:    ProviderKindNative,
					Module:  strings.Repeat("m", 63),
					Failure: providerFailureIndeterminate,
				},
			},
		},
	}}}

	err := Validate(document)

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.namespaces."+namespace+".providers."+name+".module", pathError.Path)
}

func TestGenericNativeProviderRejectsLocalNameOutsidePublicComponentGrammar(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`policy:
  namespaces:
    dkim2:
      providers:
        risk-score:
          kind: native
          module: reputation
          failure: indeterminate
          timeout: 100ms
`))
	requireNoError(t, err)

	err = Validate(document)

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.namespaces.dkim2.providers.risk-score", pathError.Path)
}

func TestGenericNativeProviderAcceptsExactCanonicalProviderReferences(t *testing.T) {
	document := decodeGenericNativeProviderReferences(t, "dkim2/plugin.reputation.risk")

	requireNoError(t, Validate(document))
}

func TestGenericNativeProviderRejectsForeignAndMalformedProviderReferences(t *testing.T) {
	tests := []string{
		"dkim2/plugin.reputation.risk.extra",
		"dkim2/plugin.foreign.risk",
		"dkim2/plugin.reputation.other",
		"mail/plugin.reputation.risk",
		"dkim2/plugin.reputation-provider.risk",
		"dkim2/plugin.reputation",
		"dkim2/plugin.reputation.Risk",
	}

	for _, providerUse := range tests {
		t.Run(providerUse, func(t *testing.T) {
			document := decodeGenericNativeProviderReferences(t, providerUse)

			err := Validate(document)

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(
				t,
				"policy.namespaces.dkim2.domain_plans.configured.checkpoints.final_decision.providers[0].use",
				pathError.Path,
			)
		})
	}
}

func TestGenericNativeProviderReferencesPreserveLegacyAuthnPluginIdentity(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`policy:
  namespaces:
    authn:
      providers:
        plugin.example.module.environment:
          kind: plugin
          module: example.module
      domain_plans:
        configured:
          checkpoints:
            pre_auth:
              providers:
                - name: environment
                  use: authn/plugin.example.module.environment
`))
	requireNoError(t, err)
	requireNoError(t, Validate(document))
}

// decodeGenericNativeProviderReferences binds one authored checkpoint and effect to a provider use.
func decodeGenericNativeProviderReferences(t *testing.T, providerUse string) Document {
	t.Helper()

	document, err := Decode("yaml", strings.NewReader(`policy:
  namespaces:
    dkim2:
      providers:
        risk:
          kind: native
          module: reputation
          failure: indeterminate
          timeout: 100ms
      effects:
        notify:
          kind: obligation
          execution: host_sync
          provider: dkim2/plugin.reputation.risk
      domain_plans:
        configured:
          checkpoints:
            final_decision:
              providers:
                - name: risk
                  use: `+providerUse+`
`))
	requireNoError(t, err)

	return document
}

// decodeGenericNativeProvider decodes one provider body inside a generic namespace.
func decodeGenericNativeProvider(t *testing.T, provider string) Document {
	t.Helper()

	document, err := Decode("yaml", strings.NewReader(`policy:
  namespaces:
    dkim2:
      providers:
        risk:`+provider))
	requireNoError(t, err)

	return document
}
