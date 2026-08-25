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

var invalidGenericLuaProviders = []policyValidationPathCase{
	{
		name: "missing module",
		source: `
          kind: lua
          script_path: /etc/nauthilus/lua/reputation.lua
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.module",
	},
	{
		name: "noncanonical module",
		source: `
          kind: lua
          module: Reputation.Provider
          script_path: /etc/nauthilus/lua/reputation.lua
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.module",
	},
	{
		name: "missing script",
		source: `
          kind: lua
          module: reputation
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.script_path",
	},
	{
		name: "foreign Lua authority",
		source: `
          kind: lua
          module: reputation
          script_path: /etc/nauthilus/lua/reputation.lua
          produced_facts: [lua.foreign.score]
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.produced_facts[0]",
	},
	{
		name: "foreign source",
		source: `
          kind: lua
          module: reputation
          script_path: /etc/nauthilus/lua/reputation.lua
          produced_facts: [plugin.reputation.score]
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.produced_facts[0]",
	},
	{
		name: "duplicate output",
		source: `
          kind: lua
          module: reputation
          script_path: /etc/nauthilus/lua/reputation.lua
          produced_facts: [lua.reputation.score, lua.reputation.score]
          failure: indeterminate
          timeout: 100ms
`,
		path: "policy.namespaces.dkim2.providers.risk.produced_facts[1]",
	},
}

func TestGenericLuaProviderOwnsSeparateAuthorityBoundConfiguration(t *testing.T) {
	document := decodeGenericLuaProvider(t, `
          kind: lua
          module: reputation
          script_path: /etc/nauthilus/lua/reputation.lua
          produced_facts: [lua.reputation.score]
          failure: continue
          timeout: 100ms
`)

	requireNoError(t, Validate(document))
}

func TestGenericLuaProviderRejectsInvalidBindingConfiguration(t *testing.T) {
	for _, test := range invalidGenericLuaProviders {
		t.Run(test.name, func(t *testing.T) {
			document := decodeGenericLuaProvider(t, test.source)

			err := Validate(document)

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, test.path, pathError.Path)
		})
	}
}

func TestLegacyLuaProviderKindsRemainAuthnOnly(t *testing.T) {
	for _, kind := range []string{providerKindLuaEnvironment, providerKindLuaSubject} {
		t.Run(kind, func(t *testing.T) {
			document := decodeGenericLuaProvider(t, `
          kind: `+kind+`
          script_path: /etc/nauthilus/lua/legacy.lua
          failure: indeterminate
          timeout: 100ms
`)

			err := Validate(document)

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, "policy.namespaces.dkim2.providers.risk.kind", pathError.Path)
		})
	}

	authnDocument, err := Decode("yaml", strings.NewReader(`policy:
  namespaces:
    authn:
      providers:
        lua_environment_legacy:
          kind: lua_environment
          script_path: /etc/nauthilus/lua/environment.lua
`))
	requireNoError(t, err)
	requireNoError(t, Validate(authnDocument))
}

// decodeGenericLuaProvider decodes one provider body inside a generic namespace.
func decodeGenericLuaProvider(t *testing.T, provider string) Document {
	t.Helper()

	document, err := Decode("yaml", strings.NewReader(`policy:
  namespaces:
    dkim2:
      providers:
        risk:`+provider))
	requireNoError(t, err)

	return document
}
