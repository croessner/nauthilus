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

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/spf13/viper"
)

func TestPolicyCutoverInstallsProductionRootAuthority(t *testing.T) {
	wantRoots := []string{"runtime", "observability", "storage", "auth", "identity", "plugins", "policy"}
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

	field, ok := settingsType.FieldByName("Policy")
	if !ok {
		t.Fatal("FileSettings.Policy is missing")
	}

	if got, want := field.Type, reflect.TypeFor[policyconfig.PolicyConfig](); got != want {
		t.Fatalf("FileSettings.Policy type = %v, want %v", got, want)
	}
}

func TestPolicyCutoverRemovesLegacyAuthPolicyAuthority(t *testing.T) {
	authType := reflect.TypeFor[AuthSection]()

	if _, ok := authType.FieldByName("Policy"); ok {
		t.Fatal("AuthSection.Policy exists after the hard cutover")
	}

	if _, ok := reflect.TypeFor[*FileSettings]().MethodByName("GetAuthPolicy"); ok {
		t.Fatal("FileSettings.GetAuthPolicy exists after the hard cutover")
	}

	method, ok := reflect.TypeFor[*FileSettings]().MethodByName("GetPolicy")
	if !ok {
		t.Fatal("FileSettings.GetPolicy is missing")
	}

	wantMethod := reflect.TypeFor[func(*FileSettings) policyconfig.PolicyConfig]()
	if method.Type != wantMethod {
		t.Fatalf("FileSettings.GetPolicy type = %v, want %v", method.Type, wantMethod)
	}
}

func TestPolicyCutoverProductionRootIsPresentInSyntaxKeys(t *testing.T) {
	roots, _, _, err := KnownConfigSyntaxKeys()
	if err != nil {
		t.Fatalf("KnownConfigSyntaxKeys() error = %v", err)
	}

	if !slices.Contains(roots, "policy") {
		t.Fatalf("KnownConfigSyntaxKeys() roots = %v, want policy root", roots)
	}
}

func TestPolicyCutoverProductionRootIsAcceptedByProductionDecoder(t *testing.T) {
	reader := viper.New()
	reader.Set("policy", map[string]any{
		"api": map[string]any{
			"enabled": true,
		},
	})

	cfg := &FileSettings{}

	if err := cfg.handleFile(reader); err != nil {
		t.Fatalf("handleFile() error = %v", err)
	}

	policyConfig := cfg.GetPolicy()
	if !policyConfig.API.Enabled {
		t.Fatal("GetPolicy().API.Enabled = false, want true")
	}

	if got, want := policyConfig.API.Limits.MaxRequestBytes, 1<<20; got != want {
		t.Fatalf("GetPolicy().API.Limits.MaxRequestBytes = %d, want %d", got, want)
	}
}

func TestPolicyCutoverProductionDecoderRejectsLegacyAuthRoot(t *testing.T) {
	reader := viper.New()
	reader.Set("auth.policy.mode", "enforce")

	err := (&FileSettings{}).handleFile(reader)
	if err == nil {
		t.Fatal("handleFile() error = nil, want legacy root rejection")
	}

	if !strings.Contains(err.Error(), "auth.policy") {
		t.Fatalf("handleFile() error = %q, want auth.policy path", err)
	}
}
