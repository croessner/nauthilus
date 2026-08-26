// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
)

func TestTopLevelExampleSelectsOnlyCanonicalAuthenticationEffect(t *testing.T) {
	registry, _, _ := registerTestPlugin(t, testModule(map[string]any{}, true))
	if providers := registry.DecisionEffectProviders(); len(providers) != 0 {
		t.Fatalf("generic effect providers = %d, want none for credential-dependent HIBP semantics", len(providers))
	}

	content := readHIBPPolicyExample(t)
	for _, unsupported := range []string{"\nauth:\n", "\n  policy:\n", "kind: native", "id: authn/haveibeenpwnd.post_action"} {
		if strings.Contains(content, unsupported) {
			t.Errorf("top-level example claims unsupported generic effect contract %q", unsupported)
		}
	}

	const canonical = "id: authn/plugin.haveibeenpwnd.post_action"
	if !strings.Contains(content, canonical) || !strings.Contains(content, "`DecisionEffectProvider`") {
		t.Error("top-level example does not document the exact authn-only effect boundary")
	}

	policyStart := strings.Index(content, "\npolicy:\n")
	if policyStart < 0 {
		t.Fatal("top-level HIBP example has no Policy root")
	}

	document, err := policyconfig.Decode("yaml", strings.NewReader(content[policyStart+1:]))
	if err != nil {
		t.Fatalf("decode top-level HIBP Policy example: %v", err)
	}

	if err = policyconfig.Validate(policyconfig.Normalize(document)); err != nil {
		t.Fatalf("validate top-level HIBP Policy example: %v", err)
	}
}

// readHIBPPolicyExample returns the repository-owned module example.
func readHIBPPolicyExample(t *testing.T) string {
	t.Helper()

	path := filepath.Join("..", "..", "..", "server", "docs", "examples", "go_plugin_haveibeenpwnd.yml")

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy example %q: %v", path, err)
	}

	return string(content)
}
