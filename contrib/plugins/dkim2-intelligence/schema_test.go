package main

import "testing"

// TestChainAndPeerSchemasHaveExactIndependentVocabulary protects the normative composition boundary.
func TestChainAndPeerSchemasHaveExactIndependentVocabulary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []fieldSpec
		count  int
	}{
		{"chain", chainFields(), 34}, {"peer", peerFields(), 36},
	} {
		if len(tc.fields) != tc.count {
			t.Fatalf("%s fields=%d want %d", tc.name, len(tc.fields), tc.count)
		}

		seen := make(map[string]bool)
		for _, field := range tc.fields {
			if seen[field.Name] {
				t.Fatalf("duplicate %s field %s", tc.name, field.Name)
			}

			seen[field.Name] = true
			if field.Name == "ip" || field.Name == "subject_tag" || field.Name == "recipe_digest" {
				t.Fatal("sensitive material duplicated")
			}
		}
	}
}
