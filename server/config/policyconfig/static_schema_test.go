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

func TestPolicyStaticSchemaValidationPaths(t *testing.T) {
	tests := []struct {
		name   string
		schema string
		path   string
	}{
		{
			name: "version",
			schema: `static:
          sign-message-instance:
            versions:
              latest:
                facts: []`,
			path: "policy.namespaces.dkim2.schema_contributions.static.sign-message-instance.versions.latest",
		},
		{
			name: "fact attribute",
			schema: `static:
          sign-message-instance:
            versions:
              v1:
                facts:
                  - attribute: Invalid
                    category: environment
                    type: string
                    allowed_sources: [caller]
                    max_length: 64`,
			path: "policy.namespaces.dkim2.schema_contributions.static.sign-message-instance.versions.v1.facts[0].attribute",
		},
		{
			name: "fact source",
			schema: `static:
          sign-message-instance:
            versions:
              v1:
                facts:
                  - attribute: input.message
                    category: resource
                    type: string
                    allowed_sources: [unknown]
                    max_length: 64`,
			path: "policy.namespaces.dkim2.schema_contributions.static.sign-message-instance.versions.v1.facts[0].allowed_sources[0]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, err := Decode("yaml", strings.NewReader("policy:\n  namespaces:\n    dkim2:\n      schema_contributions:\n        "+test.schema+"\n"))
			requireNoError(t, err)

			err = Validate(document)

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, test.path, pathError.Path)
		})
	}
}

func TestPolicyStaticSchemaCannotOverrideBuiltinAuthn(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`policy:
  namespaces:
    authn:
      schema_contributions:
        static:
          authenticate:
            versions:
              v1:
                facts: []
`))
	requireNoError(t, err)

	err = Validate(document)

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.namespaces.authn.schema_contributions.static", pathError.Path)
}
