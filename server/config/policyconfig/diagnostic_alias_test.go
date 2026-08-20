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

func TestPolicyDiagnosticAliasCountsOneBoundDefinitionOnce(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`policy:
  namespaces:
    dkim2:
      policy_sets:
        default:
          diagnostics: {public_id: default}
          rules: []
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      default_policy: dkim2/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision:
          policy_sets: [dkim2/default]
`))
	requireNoError(t, err)
	requireNoError(t, Validate(document))
}
