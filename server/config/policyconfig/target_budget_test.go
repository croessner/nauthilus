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

func TestPolicyProviderDefaultFitsEvaluationBudget(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`policy:
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 3s}
`))
	requireNoError(t, err)

	err = Validate(document)

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.targets[0].timeouts.provider_default", pathError.Path)
}
