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
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestPolicyCutoverLeavesProductionRootUnchanged(t *testing.T) {
	wantRoots := []string{"runtime", "observability", "storage", "auth", "identity", "plugins"}
	settingsType := reflect.TypeFor[FileSettings]()
	gotRoots := make([]string, 0, len(wantRoots))

	for field := range settingsType.Fields() {
		tag := field.Tag.Get("mapstructure")

		name, options, _ := strings.Cut(tag, ",")
		if name == "-" || strings.Contains(options, "remain") {
			continue
		}

		gotRoots = append(gotRoots, name)
	}

	if !slices.Equal(gotRoots, wantRoots) {
		t.Fatalf("FileSettings roots = %v, want %v", gotRoots, wantRoots)
	}

	if _, ok := settingsType.FieldByName("Policy"); ok {
		t.Fatal("FileSettings.Policy exists, want standalone policy schema only")
	}
}

func TestPolicyCutoverPreservesLegacyAuthPolicyAuthority(t *testing.T) {
	authType := reflect.TypeFor[AuthSection]()

	field, ok := authType.FieldByName("Policy")
	if !ok {
		t.Fatal("AuthSection.Policy is missing, want legacy production authority")
	}

	if got, want := field.Tag.Get("mapstructure"), "policy"; got != want {
		t.Fatalf("AuthSection.Policy mapstructure tag = %q, want %q", got, want)
	}

	if got, want := field.Type, reflect.TypeFor[AuthPolicySection](); got != want {
		t.Fatalf("AuthSection.Policy type = %v, want %v", got, want)
	}

	method, ok := reflect.TypeFor[*FileSettings]().MethodByName("GetAuthPolicy")
	if !ok {
		t.Fatal("FileSettings.GetAuthPolicy is missing, want legacy production reader")
	}

	wantMethod := reflect.TypeFor[func(*FileSettings) AuthPolicySection]()
	if method.Type != wantMethod {
		t.Fatalf("FileSettings.GetAuthPolicy type = %v, want %v", method.Type, wantMethod)
	}
}

func TestPolicyCutoverStandaloneRootIsAbsentFromProductionSyntaxKeys(t *testing.T) {
	roots, _, _, err := KnownConfigSyntaxKeys()
	if err != nil {
		t.Fatalf("KnownConfigSyntaxKeys() error = %v", err)
	}

	if slices.Contains(roots, "policy") {
		t.Fatalf("KnownConfigSyntaxKeys() roots = %v, want no standalone policy root", roots)
	}
}

func TestPolicyCutoverStandaloneRootIsRejectedByProductionDecoder(t *testing.T) {
	reader := viper.New()
	reader.Set("policy", map[string]any{
		"api": map[string]any{
			"enabled": true,
		},
	})

	cfg := &FileSettings{}

	err := cfg.handleFile(reader)
	if err == nil {
		t.Fatal("handleFile() error = nil, want standalone policy root rejection")
	}

	want := "configuration errors: field 'policy.api.enabled' is not a supported configuration key"
	if err.Error() != want {
		t.Fatalf("handleFile() error = %q, want %q", err, want)
	}
}
