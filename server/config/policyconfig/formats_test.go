// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

const (
	canonicalRoundTripJSON = `{"policy":{"targets":[{"namespace":"dkim2","action":"sign-message-instance","schema":"dkim2/sign-message-instance/v1","no_match":"deny","timeouts":{"evaluation":"2s","provider_default":"500ms"}}]}}`
	canonicalRoundTripTOML = `[[policy.targets]]
namespace = "dkim2"
action = "sign-message-instance"
schema = "dkim2/sign-message-instance/v1"
no_match = "deny"
[policy.targets.timeouts]
evaluation = "2s"
provider_default = "500ms"
`
	canonicalRoundTripYAML = `policy:
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      no_match: deny
      timeouts:
        evaluation: 2s
        provider_default: 500ms
`
	canonicalRoundTripHCL = `policy {
  targets = [{
    namespace = "dkim2"
    action = "sign-message-instance"
    schema = "dkim2/sign-message-instance/v1"
    no_match = "deny"
    timeouts = { evaluation = "2s", provider_default = "500ms" }
  }]
}
`
	canonicalRoundTripTFVars = `policy = {
  targets = [{
    namespace = "dkim2"
    action = "sign-message-instance"
    schema = "dkim2/sign-message-instance/v1"
    no_match = "deny"
    timeouts = { evaluation = "2s", provider_default = "500ms" }
  }]
}
`
	canonicalRoundTripFlat = `policy.targets[0].namespace=dkim2
policy.targets[0].action=sign-message-instance
policy.targets[0].schema=dkim2/sign-message-instance/v1
policy.targets[0].no_match=deny
policy.targets[0].timeouts.evaluation=2s
policy.targets[0].timeouts.provider_default=500ms
`
	canonicalRoundTripINI = `[policy.targets[0]]
namespace=dkim2
action=sign-message-instance
schema=dkim2/sign-message-instance/v1
no_match=deny
[policy.targets[0].timeouts]
evaluation=2s
provider_default=500ms
`
)

func TestPolicySupportedFormatsMatchViperAuthority(t *testing.T) {
	got := SupportedFormats()

	want := append([]string(nil), viper.SupportedExts...)

	slices.Sort(got)
	slices.Sort(want)
	requireEqual(t, strings.Join(want, ","), strings.Join(got, ","))
}

func TestPolicySupportedFormatsDecodeSameContract(t *testing.T) {
	formats := map[string]string{
		"json":       `{"policy":{"api":{"enabled":true}}}`,
		"toml":       "[policy.api]\nenabled = true\n",
		"yaml":       "policy:\n  api:\n    enabled: true\n",
		"yml":        "policy:\n  api:\n    enabled: true\n",
		"properties": "policy.api.enabled=true\n",
		"props":      "policy.api.enabled=true\n",
		"prop":       "policy.api.enabled=true\n",
		"hcl":        "policy { api { enabled = true } }\n",
		"tfvars":     "policy = { api = { enabled = true } }\n",
		"dotenv":     "policy.api.enabled=true\n",
		"env":        "policy.api.enabled=true\n",
		"ini":        "[policy.api]\nenabled=true\n",
	}

	requireEqual(t, len(formats), len(SupportedFormats()))

	for _, format := range SupportedFormats() {
		t.Run(format, func(t *testing.T) {
			document, err := Decode(format, strings.NewReader(formats[format]))
			requireNoError(t, err)

			if !document.Policy.API.Enabled {
				t.Fatalf("%s did not preserve policy.api.enabled", format)
			}
		})
	}
}

func TestPolicyFlatFormatDecodesIndexedTargets(t *testing.T) {
	document, err := Decode("properties", strings.NewReader(`
policy.targets[0].namespace=dkim2
policy.targets[0].action=sign-message-instance
policy.targets[0].schema=dkim2/sign-message-instance/v1
policy.targets[0].no_match=deny
policy.targets[0].timeouts.evaluation=2s
policy.targets[0].timeouts.provider_default=500ms
`))
	requireNoError(t, err)
	requireEqual(t, 1, len(document.Policy.Targets))
	requireEqual(t, "dkim2", document.Policy.Targets[0].Namespace)
	requireNoError(t, Validate(Normalize(document)))
}

func TestPolicyFlatFormatsDecodeEscapedDottedNamespace(t *testing.T) {
	flat := `policy.namespaces.example\.mail.schema_contributions.lua.registry_scripts[0]=registry.lua
`
	formats := map[string]string{
		"properties": flat,
		"props":      flat,
		"prop":       flat,
		"dotenv":     flat,
		"env":        flat,
		"ini": `[policy.namespaces.example\.mail.schema_contributions.lua]
registry_scripts[0]=registry.lua
`,
	}

	for _, format := range []string{"properties", "props", "prop", "dotenv", "env", "ini"} {
		t.Run(format, func(t *testing.T) {
			document, err := Decode(format, strings.NewReader(formats[format]))
			requireNoError(t, err)

			namespace, exists := document.Policy.Namespaces["example.mail"]
			if !exists {
				t.Fatal("escaped dotted namespace was not preserved as one map key")
			}

			requireEqual(t, 1, len(namespace.SchemaContributions.Lua.RegistryScripts))
			requireEqual(t, "registry.lua", namespace.SchemaContributions.Lua.RegistryScripts[0])
		})
	}
}

func TestPolicyFlatFormatsRejectDuplicateEscapedDottedNamespacePath(t *testing.T) {
	flat := `policy.namespaces.example\.mail.schema_contributions.lua.registry_scripts[0]=first.lua
policy.namespaces.example\.mail.schema_contributions.lua.registry_scripts[0]=second.lua
`
	formats := map[string]string{
		"properties": flat,
		"props":      flat,
		"prop":       flat,
		"dotenv":     flat,
		"env":        flat,
		"ini": `[policy.namespaces.example\.mail.schema_contributions.lua]
registry_scripts[0]=first.lua
registry_scripts[0]=second.lua
`,
	}

	for _, format := range []string{"properties", "props", "prop", "dotenv", "env", "ini"} {
		t.Run(format, func(t *testing.T) {
			_, err := Decode(format, strings.NewReader(formats[format]))
			if err == nil {
				t.Fatal("duplicate escaped namespace path was accepted")
			}

			if !strings.Contains(err.Error(), "duplicate configuration path") {
				t.Fatalf("unexpected duplicate-path error: %v", err)
			}
		})
	}
}

func TestPolicySupportedFormatCanonicalRoundTrips(t *testing.T) {
	fixtures, expected := policyCanonicalRoundTripFixtures(), ""

	for _, format := range SupportedFormats() {
		document, err := Decode(format, strings.NewReader(fixtures[format]))
		requireNoError(t, err)

		canonical, err := Canonical(document)
		requireNoError(t, err)

		if expected == "" {
			expected = canonical.String()

			continue
		}

		requireEqual(t, expected, canonical.String())
	}
}

// policyCanonicalRoundTripFixtures returns equivalent documents for every supported format.
func policyCanonicalRoundTripFixtures() map[string]string {
	fixtures := map[string]string{
		"json":   canonicalRoundTripJSON,
		"toml":   canonicalRoundTripTOML,
		"yaml":   canonicalRoundTripYAML,
		"yml":    canonicalRoundTripYAML,
		"hcl":    canonicalRoundTripHCL,
		"tfvars": canonicalRoundTripTFVars,
		"ini":    canonicalRoundTripINI,
	}

	for _, format := range []string{"properties", "props", "prop", "dotenv", "env"} {
		fixtures[format] = canonicalRoundTripFlat
	}

	return fixtures
}

func TestPolicyJSONRejectsDuplicateFields(t *testing.T) {
	_, err := Decode("json", strings.NewReader(`{"policy":{"api":{"enabled":true,"enabled":false}}}`))

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.api.enabled", pathError.Path)
}
