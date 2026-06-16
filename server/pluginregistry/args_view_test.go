package pluginregistry

import "testing"

const argsViewNestedKey = "nested"

func TestArgsViewIsReadOnlyAndStrictDecode(t *testing.T) {
	view := NewArgsView(map[string]any{
		"action": "notify",
		argsViewNestedKey: map[string]any{
			"enabled": true,
		},
	})

	value, ok := view.Sub(argsViewNestedKey).Get("enabled")
	if !ok || value != true {
		t.Fatalf("nested.enabled = %#v/%t, want true", value, ok)
	}

	got, ok := view.GetPath([]string{argsViewNestedKey})
	if !ok {
		t.Fatal("missing nested map")
	}

	nested := got.(map[string]any)
	nested["enabled"] = false

	value, ok = view.Sub(argsViewNestedKey).Get("enabled")
	if !ok || value != true {
		t.Fatalf("nested.enabled after caller mutation = %#v/%t, want true", value, ok)
	}

	var strict struct {
		Action string `mapstructure:"action"`
	}
	if err := view.Decode(&strict); err == nil {
		t.Fatal("Decode() error = nil, want unused-field error")
	}
}
