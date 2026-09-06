package pluginruntime

import (
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"testing"
)

// TestModuleHostConfigIdentityCannotBeConfigured binds startup identity to the actual module owner.
func TestModuleHostConfigIdentityCannotBeConfigured(t *testing.T) {
	host := NewHost(WithConfig(pluginregistry.NewConfigView(map[string]any{"host_context": map[string]any{"module_name": "forged"}})))
	view := host.moduleHost("actual").Config()

	value, ok := view.Get("host_context.module_name")
	if !ok || value != "actual" {
		t.Fatal("module identity is not host-bound")
	}
}
