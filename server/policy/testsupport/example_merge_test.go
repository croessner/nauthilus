package testsupport

import (
	"reflect"
	"testing"
)

// TestMergeExamplePreservesComponentBindings protects composed observation and decision schedules.
func TestMergeExamplePreservesComponentBindings(t *testing.T) {
	cases := []struct {
		name     string
		base     []any
		addition []any
		want     []any
	}{
		{
			name:     "distinct geographic components",
			base:     []any{map[string]any{"component": "observation", "targets": []any{"reputation/observe"}}},
			addition: []any{map[string]any{"component": "smtp_peer", "targets": []any{"dkim2/accept-message-instance"}}},
			want: []any{
				map[string]any{"component": "observation", "targets": []any{"reputation/observe"}},
				map[string]any{"component": "smtp_peer", "targets": []any{"dkim2/accept-message-instance"}},
			},
		},
		{
			name:     "same component merges configuration",
			base:     []any{map[string]any{"component": "observation", "output_fact": "observations"}},
			addition: []any{map[string]any{"component": "observation", "targets": []any{"reputation/observe"}}},
			want: []any{map[string]any{
				"component": "observation", "output_fact": "observations", "targets": []any{"reputation/observe"},
			}},
		},
		{
			name:     "distinct components on one target",
			base:     []any{map[string]any{"component": "assessment", "target": "dkim2/accept-message-instance"}},
			addition: []any{map[string]any{"component": "audit", "target": "dkim2/accept-message-instance"}},
			want: []any{
				map[string]any{"component": "assessment", "target": "dkim2/accept-message-instance"},
				map[string]any{"component": "audit", "target": "dkim2/accept-message-instance"},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := MergeExample(testCase.base, testCase.addition)
			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("component bindings differ: got %#v, want %#v", got, testCase.want)
			}
		})
	}
}
