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

func TestPolicyProviderKindUsesClosedVocabulary(t *testing.T) {
	document, err := Decode("yaml", strings.NewReader(`policy:
  namespaces:
    dkim2:
      providers:
        risk:
          kind: arbitrary_provider
          failure: indeterminate
          timeout: 100ms
`))
	requireNoError(t, err)

	err = Validate(document)

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, "policy.namespaces.dkim2.providers.risk.kind", pathError.Path)
}
