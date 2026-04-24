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

package config

import (
	"slices"
	"testing"
)

func TestConfigPathFromStructNamespace_UsesMapstructureTags(t *testing.T) {
	schemaIndex, err := getConfigSchemaIndex()
	if err != nil {
		t.Fatalf("getConfigSchemaIndex() error = %v", err)
	}

	got := schemaIndex.configPathFromStructNamespace("FileSettings.Identity.OIDC.Clients[0].ClientID")
	want := "identity.oidc.clients[0].client_id"

	if got != want {
		t.Fatalf("configPathFromStructNamespace() = %q, want %q", got, want)
	}
}

func TestKnownConfigSyntaxKeys_IncludeNestedListAndMappingKeys(t *testing.T) {
	_, _, level3, err := KnownConfigSyntaxKeys()
	if err != nil {
		t.Fatalf("KnownConfigSyntaxKeys() error = %v", err)
	}

	for _, key := range []string{"script_path", "when_no_auth", "name", "mappings"} {
		if !slices.Contains(level3, key) {
			t.Fatalf("KnownConfigSyntaxKeys() missing %q", key)
		}
	}
}
