// Copyright (C) 2026 Christian Rößner
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
)

// TestProductionPolicyDecodePreservesNumericKinds covers the production settings-to-policy boundary.
func TestProductionPolicyDecodePreservesNumericKinds(t *testing.T) {
	assertPolicyNumericKinds(t, "gte", false)
}

// TestMergedPolicyPublicationPreservesNumericKinds covers final Viper publication before runtime preparation.
func TestMergedPolicyPublicationPreservesNumericKinds(t *testing.T) {
	assertPolicyNumericKinds(t, "eq", true)
}

// assertPolicyNumericKinds checks exact authored integer and double kinds through each production boundary.
func assertPolicyNumericKinds(t *testing.T, operator string, publish bool) {
	t.Helper()

	for _, scalar := range []string{"64500", "1", "20", "20.0", "0.0", "0.7", "2e1"} {
		t.Run(scalar, func(t *testing.T) {
			settings := policyNumericSettings(t, operator, scalar)

			if publish {
				settings = publishPolicyNumericSettings(t, settings)
			}

			document, err := decodePolicyConfiguration(settings)
			if err != nil {
				t.Fatal(err)
			}

			expression := document.Policy.Namespaces["mail"].PolicySets["filter"].Rules[0].If
			value := expression.Eq

			if operator == "gte" {
				value = expression.GTE
			}

			number, ok := value.(json.Number)
			if !ok {
				t.Fatal("Policy scalar lost its numeric representation")
			}

			_, integerErr := number.Int64()
			if (integerErr != nil) != strings.ContainsAny(scalar, ".eE") {
				t.Fatalf("authored scalar %s became %s", scalar, number)
			}
		})
	}
}

// policyNumericSettings decodes authored YAML through the same bounded reader used by configuration loading.
func policyNumericSettings(t *testing.T, operator, scalar string) map[string]any {
	t.Helper()

	source := fmt.Sprintf("policy:\n  namespaces:\n    mail:\n      policy_sets:\n        filter:\n          rules:\n            - name: sample\n              if: {attribute: plugin.test.value, %s: %s}\n              then: {decision: deny}\n", operator, scalar)

	settings, err := policyconfig.DecodeSettings("yaml", strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}

	return settings
}

// publishPolicyNumericSettings also proves Viper normalization cannot mutate the validated source tree.
func publishPolicyNumericSettings(t *testing.T, settings map[string]any) map[string]any {
	t.Helper()

	reader := viper.New()
	settings["fixture"] = map[string]any{"OpaqueCase": []any{map[string]any{"Field": 42}}}
	original := policyconfig.CloneSettings(settings)

	if err := applyMergedConfigSettingsTo(reader, settings, "yaml", ""); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(settings, original) {
		t.Fatal("Viper publication mutated the validated source settings")
	}

	return reader.AllSettings()
}
