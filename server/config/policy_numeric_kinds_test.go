// Copyright (C) 2026 Christian Rößner
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
)

// TestProductionPolicyDecodePreservesNumericKinds covers the production settings-to-policy boundary.
func TestProductionPolicyDecodePreservesNumericKinds(t *testing.T) {
	for _, scalar := range []string{"20.0", "20", "0.0", "0.7", "2e1"} {
		t.Run(scalar, func(t *testing.T) {
			source := fmt.Sprintf("policy:\n  namespaces:\n    mail:\n      policy_sets:\n        filter:\n          rules:\n            - name: sample\n              if: {attribute: plugin.test.samples, gte: %s}\n              then: {decision: deny}\n", scalar)

			settings, err := policyconfig.DecodeSettings("yaml", strings.NewReader(source))
			if err != nil {
				t.Fatal(err)
			}

			document, err := decodePolicyConfiguration(settings)
			if err != nil {
				t.Fatal(err)
			}

			number, ok := document.Policy.Namespaces["mail"].PolicySets["filter"].Rules[0].If.GTE.(json.Number)
			if !ok {
				t.Fatal("production policy threshold lost its numeric representation")
			}

			_, integerErr := number.Int64()
			if (integerErr != nil) != strings.ContainsAny(scalar, ".eE") {
				t.Fatalf("authored scalar %s became %s", scalar, number)
			}
		})
	}
}
