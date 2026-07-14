// Copyright (C) 2026 Christian Rößner
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

package policy

import "testing"

func TestPluginEnvironmentIdentity(t *testing.T) {
	tests := []struct {
		name       string
		configRef  string
		moduleName string
	}{
		{name: "valid", configRef: "plugins.modules.rns_auth.environment", moduleName: "rns_auth"},
		{name: "trimmed", configRef: " plugins.modules.rns_auth.environment ", moduleName: "rns_auth"},
		{name: "wrong suffix", configRef: "plugins.modules.rns_auth.subject"},
		{name: "missing module", configRef: "plugins.modules..environment"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := PluginEnvironmentModuleNameFromConfigRef(testCase.configRef); got != testCase.moduleName {
				t.Fatalf("PluginEnvironmentModuleNameFromConfigRef() = %q, want %q", got, testCase.moduleName)
			}
		})
	}

	if got := PluginEnvironmentCheckName("rns_auth"); got != "plugin_environment_rns_auth" {
		t.Fatalf("PluginEnvironmentCheckName() = %q", got)
	}

	if got := PluginEnvironmentConfigRef("rns_auth"); got != "plugins.modules.rns_auth.environment" {
		t.Fatalf("PluginEnvironmentConfigRef() = %q", got)
	}

	if got := PluginEnvironmentAttributeID("rns_auth", "blocklist", "triggered"); got != "auth.plugin.environment.rns_auth.blocklist.triggered" {
		t.Fatalf("PluginEnvironmentAttributeID() = %q", got)
	}
}
