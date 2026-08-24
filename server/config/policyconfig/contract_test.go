// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"errors"
	"strings"
	"testing"
)

type policyValidationPathCase struct {
	name   string
	source string
	path   string
}

var policyValidationPathCases = []policyValidationPathCase{
	{
		name: "exported set requires complete contract",
		source: `policy:
  namespaces:
    shared:
      policy_sets:
        deny:
          visibility: exported
          export_contract:
            compatible_checkpoints: [final_decision]
`,
		path: "policy.namespaces.shared.policy_sets.deny.export_contract.required_facts",
	},
	{
		name: "effect execution is mandatory",
		source: `policy:
  namespaces:
    dkim2:
      effects:
        return_reason:
          kind: obligation
          targets:
            - action: sign-message-instance
`,
		path: "policy.namespaces.dkim2.effects.return_reason.execution",
	},
	{
		name: "generic provider failure is mandatory",
		source: `policy:
  namespaces:
    dkim2:
      providers:
        risk:
          kind: lua_environment
          targets:
            - action: sign-message-instance
          executions: [host_sync]
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.failure",
	},
	{
		name: "generic target no match is mandatory",
		source: `policy:
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      timeouts:
        evaluation: 2s
        provider_default: 500ms
`,
		path: "policy.targets[0].no_match",
	},
	{
		name: "schema version is exact",
		source: `policy:
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/latest
      no_match: deny
      timeouts:
        evaluation: 2s
        provider_default: 500ms
`,
		path: "policy.targets[0].schema",
	},
	{
		name: "diagnostic alias is bounded",
		source: `policy:
  namespaces:
    shared:
      policy_sets:
        deny:
          diagnostics:
            public_id: ../private/path
`,
		path: "policy.namespaces.shared.policy_sets.deny.diagnostics.public_id",
	},
}

var providerAndEffectValidationPathCases = []policyValidationPathCase{
	{
		name: "invalid provider failure",
		source: `policy:
  namespaces:
    dkim2:
      providers:
        risk:
          kind: native
          failure: abort
`,
		path: "policy.namespaces.dkim2.providers.risk.failure",
	},
	{
		name: "host effect requires provider",
		source: `policy:
  namespaces:
    dkim2:
      effects:
        notify:
          kind: obligation
          execution: host_sync
`,
		path: "policy.namespaces.dkim2.effects.notify.provider",
	},
	{
		name: "return effect forbids provider",
		source: `policy:
  namespaces:
    dkim2:
      effects:
        reason:
          kind: advice
          execution: return_only
          provider: dkim2/dispatch
`,
		path: "policy.namespaces.dkim2.effects.reason.provider",
	},
	{
		name: "post action requires post execution",
		source: `policy:
  namespaces:
    authn:
      effects:
        notify:
          kind: lua_action
          action_type: post
          execution: host_sync
          provider: authn/dispatch
`,
		path: "policy.namespaces.authn.effects.notify.execution",
	},
}

func TestPolicyStandaloneDecodeAndNormalize(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`
policy:
  namespaces:
    shared:
      policy_sets:
        deny:
          rules: []
`))
	requireNoError(t, err)

	normalized := Normalize(document)
	requireEqual(t, VisibilityPrivate, normalized.Policy.Namespaces["shared"].PolicySets["deny"].Visibility)
	requireNoError(t, Validate(normalized))
}

func TestPolicyNormalizeAppliesFiniteCallerAdmissionLimits(t *testing.T) {
	normalized := Normalize(Document{})
	limits := normalized.Policy.API.Limits

	want := APILimitsConfig{
		MaxRequestBytes:            1 << 20,
		MaxFacts:                   512,
		PerClientConcurrency:       8,
		PerClientRequestsPerSecond: 25,
	}

	if limits.MaxRequestBytes != want.MaxRequestBytes ||
		limits.MaxFacts != want.MaxFacts ||
		limits.PerClientConcurrency != want.PerClientConcurrency ||
		limits.PerClientRequestsPerSecond != want.PerClientRequestsPerSecond {
		t.Fatalf("normalized caller admission limits = %+v, want %+v", limits, want)
	}
}

func TestPolicyNormalizeOwnsNestedMutableState(t *testing.T) {
	document := Document{Policy: PolicyConfig{Namespaces: map[string]NamespaceConfig{
		"shared": {
			PolicySets: map[string]PolicySetConfig{"default": {}},
			Effects: map[string]EffectConfig{
				"notify": {
					Parameters: map[string]EffectParameterConfig{"message": {Type: "string"}},
				},
			},
		},
	}}}

	normalized := Normalize(document)
	namespace := normalized.Policy.Namespaces["shared"]
	effect := namespace.Effects["notify"]
	parameter := effect.Parameters["message"]
	parameter.MaxLength = 64
	effect.Parameters["message"] = parameter
	namespace.Effects["notify"] = effect
	normalized.Policy.Namespaces["shared"] = namespace

	requireEqual(t, "", document.Policy.Namespaces["shared"].PolicySets["default"].Visibility)
	requireEqual(t, 0, document.Policy.Namespaces["shared"].Effects["notify"].Parameters["message"].MaxLength)
}

func TestPolicyValidationPaths(t *testing.T) {
	assertPolicyValidationPaths(t, policyValidationPathCases, func(document Document) error {
		return Validate(Normalize(document))
	})
}

func TestPolicyUnknownAndForbiddenFields(t *testing.T) {
	fields := []string{
		"config_ref",
		"stage",
		"retry_safety",
		"idempotency_parameter",
		"idempotency_key",
		"retry_token",
		"deduplication_key",
	}

	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			input := "policy:\n  namespaces:\n    dkim2:\n      providers:\n        risk:\n          kind: lua_environment\n          " + field + ": rejected\n"
			_, err := Decode("yaml", strings.NewReader(input))

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, "policy.namespaces.dkim2.providers.risk."+field, pathError.Path)
		})
	}
}

func TestPolicyCanonicalRedactsSecretsAndSharesPaths(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`
policy:
  api:
    clients:
      - principal: local-dkim2
        authentication:
          basic:
            username: dkim2
            password: top-secret
        authentication_kinds: [basic]
`))
	requireNoError(t, err)

	canonical, err := Canonical(Normalize(document))
	requireNoError(t, err)
	requireEqual(t, RedactedValue, canonical.Value("policy.api.clients[0].authentication.basic.password"))

	if strings.Contains(canonical.String(), "top-secret") {
		t.Fatal("canonical projection exposed secret material")
	}

	if !contains(FieldPaths(), "policy.api.clients[].authentication.basic.password") {
		t.Fatal("field authority does not contain basic password path")
	}
}

func TestPolicyCanonicalRedactsEveryDeclaredSecretOwner(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`
policy:
  namespaces:
    dkim2:
      providers:
        signer:
          kind: native
          failure: indeterminate
          timeout: 100ms
          secrets:
            token: provider-secret
      effects:
        notify:
          kind: obligation
          execution: return_only
          targets:
            - action: sign-message-instance
          secrets:
            webhook: effect-secret
`))
	requireNoError(t, err)

	canonical, err := Canonical(document)
	requireNoError(t, err)

	paths := []string{
		"policy.namespaces.dkim2.providers.signer.secrets.token",
		"policy.namespaces.dkim2.effects.notify.secrets.webhook",
	}
	for _, path := range paths {
		requireEqual(t, RedactedValue, canonical.Value(path))
	}

	for _, secretValue := range []string{"provider-secret", "effect-secret"} {
		if strings.Contains(canonical.String(), secretValue) {
			t.Fatalf("canonical projection exposed %s", secretValue)
		}
	}
}

func TestPolicyConditionRequiresOneUnambiguousExpression(t *testing.T) {
	tests := []struct {
		name string
		body string
		path string
	}{
		{
			name: "always false",
			body: "always: false",
			path: "policy.namespaces.shared.policy_sets.deny.rules[0].if.always",
		},
		{
			name: "logical and attribute collision",
			body: "always: true\n                attribute: subject.user\n                eq: alice",
			path: "policy.namespaces.shared.policy_sets.deny.rules[0].if.attribute",
		},
		{
			name: "two attribute operators",
			body: "attribute: subject.user\n                eq: alice\n                ne: bob",
			path: "policy.namespaces.shared.policy_sets.deny.rules[0].if.ne",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := `policy:
  namespaces:
    shared:
      policy_sets:
        deny:
          rules:
            - name: deny
              checkpoint: final_decision
              if:
                ` + test.body + `
              then:
                decision: deny
`
			document, err := Decode("yaml", strings.NewReader(source))
			requireNoError(t, err)

			err = Validate(document)

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, test.path, pathError.Path)
		})
	}
}

func TestPolicyGenericObserveModeFailsAtTargetPath(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`
policy:
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      mode: observe
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
`))
	requireNoError(t, err)

	err = Validate(document)

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.targets[0].mode", pathError.Path)
}

func TestPolicyRejectsUnregisteredEffectKindAtExactPath(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`
policy:
  namespaces:
    dkim2:
      effects:
        notify:
          kind: arbitrary_action
          execution: return_only
`))
	requireNoError(t, err)

	err = Validate(document)

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.namespaces.dkim2.effects.notify.kind", pathError.Path)
}

func TestPolicyRejectsDuplicateTargetDiagnosticAliasAtSecondPath(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`
policy:
  namespaces:
    dkim2:
      providers:
        risk:
          kind: native
          targets: [{action: sign-message-instance}]
          failure: indeterminate
          timeout: 100ms
          diagnostics: {public_id: risk}
      effects:
        risk_advice:
          kind: advice
          targets: [{action: sign-message-instance}]
          execution: return_only
          diagnostics: {public_id: risk}
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
`))
	requireNoError(t, err)

	err = Validate(document)

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.namespaces.dkim2.effects.risk_advice.diagnostics.public_id", pathError.Path)
}

func TestPolicyRejectsProviderTimeoutBeyondTargetBudget(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
	}{
		{name: "evaluation", timeout: "3s"},
		{name: "provider default", timeout: "600ms"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, err := Decode("yaml", strings.NewReader(`
policy:
  namespaces:
    dkim2:
      providers:
        risk:
          kind: native
          targets: [{action: sign-message-instance}]
          failure: indeterminate
          timeout: `+test.timeout+`
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
`))
			requireNoError(t, err)

			err = Validate(document)

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, "policy.namespaces.dkim2.providers.risk.timeout", pathError.Path)
		})
	}
}

func TestPolicyProviderAndEffectValidationPaths(t *testing.T) {
	assertPolicyValidationPaths(t, providerAndEffectValidationPathCases, Validate)
}

func TestPolicyNoMatchAndTimeoutValidationPaths(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		path string
	}{
		{
			name: "invalid generic no match",
			yaml: `policy:
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      no_match: permit
      timeouts: {evaluation: 2s, provider_default: 500ms}
`,
			path: "policy.targets[0].no_match",
		},
		{
			name: "missing evaluation timeout",
			yaml: `policy:
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      no_match: deny
      timeouts: {provider_default: 500ms}
`,
			path: "policy.targets[0].timeouts.evaluation",
		},
		{
			name: "authn rejects no match",
			yaml: `policy:
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      no_match: deny
`,
			path: "policy.targets[0].no_match",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, err := Decode("yaml", strings.NewReader(test.yaml))
			requireNoError(t, err)

			err = Validate(document)

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, test.path, pathError.Path)
		})
	}
}

// assertPolicyValidationPaths verifies that every fixture fails at its expected field path.
func assertPolicyValidationPaths(t *testing.T, tests []policyValidationPathCase, validate func(Document) error) {
	t.Helper()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, err := Decode("yaml", strings.NewReader(test.source))
			requireNoError(t, err)

			err = validate(document)

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, test.path, pathError.Path)
		})
	}
}

// requireNoError fails the test when err is non-nil.
func requireNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// requireEqual fails the test when two comparable values differ.
func requireEqual[T comparable](t *testing.T, expected T, actual T) {
	t.Helper()

	if expected != actual {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

// requireErrorAs fails the test unless the error chain contains the requested type.
func requireErrorAs(t *testing.T, err error, target any) {
	t.Helper()

	if !errors.As(err, target) {
		t.Fatalf("expected matching error, got %v", err)
	}
}

// contains reports whether values contains the exact string.
func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}
