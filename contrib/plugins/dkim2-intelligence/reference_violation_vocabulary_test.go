package main

import (
	"os"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// referencePolicyPath is the operator reference Policy that consumes the violation vocabulary.
const referencePolicyPath = "../../../server/docs/examples/policy_dkim2_rspamd_verifier.yml"

// TestReferencePolicyUsesOnlyEmittedViolationClasses pins that the reference integrity rule only matches
// violation classes the plugin can emit, so the example never promises a check the plugin does not make.
func TestReferencePolicyUsesOnlyEmittedViolationClasses(t *testing.T) {
	raw, err := os.ReadFile(referencePolicyPath)
	if err != nil {
		t.Fatal(err)
	}

	var document any
	if err = yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}

	rule, ok := findNamedNode(document, "deny_integrity_violation")
	if !ok {
		t.Fatal("reference Policy has no deny_integrity_violation rule")
	}

	classes, ok := findContainsAny(rule)
	if !ok || len(classes) == 0 {
		t.Fatal("deny_integrity_violation lists no violation classes")
	}

	catalog := violationCatalog()

	for _, class := range classes {
		if !slices.Contains(catalog, class) {
			t.Errorf("deny_integrity_violation matches %q, which the plugin never emits", class)
		}
	}
}

// findNamedNode returns the first mapping whose name field equals name.
func findNamedNode(node any, name string) (map[string]any, bool) {
	switch typed := node.(type) {
	case map[string]any:
		if typed["name"] == name {
			return typed, true
		}

		for _, child := range typed {
			if found, ok := findNamedNode(child, name); ok {
				return found, true
			}
		}
	case []any:
		for _, child := range typed {
			if found, ok := findNamedNode(child, name); ok {
				return found, true
			}
		}
	}

	return nil, false
}

// findContainsAny returns the string values of the first contains_any list below node.
func findContainsAny(node any) ([]string, bool) {
	switch typed := node.(type) {
	case map[string]any:
		if values, ok := typed["contains_any"].([]any); ok {
			result := make([]string, 0, len(values))

			for _, value := range values {
				if text, isText := value.(string); isText {
					result = append(result, text)
				}
			}

			return result, true
		}

		for _, child := range typed {
			if found, ok := findContainsAny(child); ok {
				return found, true
			}
		}
	case []any:
		for _, child := range typed {
			if found, ok := findContainsAny(child); ok {
				return found, true
			}
		}
	}

	return nil, false
}
