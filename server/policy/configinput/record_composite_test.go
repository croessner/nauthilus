package configinput

import (
	"context"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
)

// TestWorkflowCompositeRecordContract exercises canonical nested predicates in a neutral namespace.
func TestWorkflowCompositeRecordContract(t *testing.T) {
	base := strings.NewReplacer("mail", "workflow", "submit", "approve").Replace(recordCollectionPolicyFixture)
	old := "field: result\n                  where: {eq: pass}"

	for _, test := range []struct {
		name  string
		where string
		valid bool
	}{
		{"same record", "where: {all: [{field: result, eq: pass}, {field: sequence, eq: 2}]}", true},
		{"nested logic", "where: {all: [{field: result, eq: pass}, {not: {any: [{field: sequence, eq: 1}, {field: sequence, eq: 3}]}}]}", true},
		{"depth boundary", "where: " + strings.Repeat("{not: ", 14) + "{field: result, eq: pass}" + strings.Repeat("}", 14), true},
		{"depth overflow", "where: " + strings.Repeat("{not: ", 15) + "{field: result, eq: pass}" + strings.Repeat("}", 15), false},
		{"integer presence", "where: {field: sequence, exists: true}", true},
		{"old syntax", old, false},
		{"empty group", "where: {all: []}", false},
		{"external fact", "where: {attribute: environment.external, eq: pass}", false},
		{"wrong type", "where: {field: sequence, eq: pass}", false},
		{"nested records", "where: {records: {attribute: resource.chain, quantifier: any, where: {field: result, eq: pass}}}", false},
		{"mixed forms", "where: {field: result, eq: pass, any: [{field: sequence, eq: 2}]}", false},
		{"two operators", "where: {field: result, eq: pass, ne: fail}", false},
		{"dynamic field", "where: {field: '${field}', eq: pass}", false},
		{"unknown field", "where: {field: unknown, eq: pass}", false},
		{"missing condition set", "where: {field: result, in: '@string.missing'}", false},
		{"empty any", "where: {any: []}", false},
		{"too deep", "where: " + strings.Repeat("{not: ", 17) + "{field: result, eq: pass}" + strings.Repeat("}", 17), false},
		{"too wide", "where: {all: [" + strings.Repeat("{field: result, eq: pass},", 65) + "]}", false},
		{"too many nodes", "where: {all: [" + strings.Repeat("{all: ["+strings.Repeat("{field: result, eq: pass},", 64)+"]},", 4) + "]}", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := strings.Replace(base, "where: {field: result, eq: pass}", test.where, 1)

			document, err := policyconfig.Decode("yaml", strings.NewReader(fixture))
			if err == nil {
				var input UnifiedPolicyInput

				input, err = Normalize(context.Background(), document)
				if err == nil {
					_, err = input.Compile(context.Background(), nil)
				}
			}

			if (err == nil) != test.valid {
				t.Fatalf("valid = %t, want %t: %v", err == nil, test.valid, err)
			}
		})
	}
}
