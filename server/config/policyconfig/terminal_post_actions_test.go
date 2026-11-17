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

// TestTerminalPostActionsValidation keeps terminal post-actions authn-only and free of repeated effect identities.
func TestTerminalPostActionsValidation(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		document string
		wantPath string
	}{
		{
			name: "generic target",
			document: `policy:
  targets:
    - namespace: delivery
      action: sign-message-instance
      schema: delivery/sign-message-instance/v1
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 1s}
      terminal_post_actions: [{id: delivery/record}]
`,
			wantPath: "policy.targets[0].terminal_post_actions",
		},
		{
			name: "repeated post-action",
			document: `policy:
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      terminal_post_actions:
        - {id: authn/plugin.clickhouse.post_action}
        - {id: authn/plugin.clickhouse.post_action}
`,
			wantPath: "policy.targets[0].terminal_post_actions[1].id",
		},
		{
			name: "unqualified identity",
			document: `policy:
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      terminal_post_actions: [{id: clickhouse}]
`,
			wantPath: "policy.targets[0].terminal_post_actions[0].id",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document, err := Decode("yaml", strings.NewReader(testCase.document))
			requireNoError(t, err)

			err = Validate(document)

			var pathError *PathError
			requireErrorAs(t, err, &pathError)
			requireEqual(t, testCase.wantPath, pathError.Path)
		})
	}
}
