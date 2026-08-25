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

func TestLegacyPluginProviderRejectsGenericNamespaceBinding(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`policy:
  namespaces:
    dkim2:
      providers:
        legacy:
          kind: plugin
          module: reputation
          failure: indeterminate
`))
	requireNoError(t, err)

	err = Validate(document)

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.namespaces.dkim2.providers.legacy.kind", pathError.Path)
}

func TestLegacyPluginProviderPreservesCanonicalAuthnBindings(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`policy:
  namespaces:
    authn:
      providers:
        plugin.example.environment:
          kind: plugin
          module: example
        plugin.example.subject.profile:
          kind: plugin
          module: example
`))
	requireNoError(t, err)
	requireNoError(t, Validate(document))
}
