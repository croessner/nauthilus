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

package pluginapi

import (
	"errors"
	"reflect"
	"testing"
)

const (
	testPluginName    = "geoip"
	testPluginVersion = "v1.2.3"
)

func TestValidateAPIVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		{name: "current", version: APIVersion},
		{name: "empty", version: "", wantErr: true},
		{name: "older", version: "nauthilus.plugin.v0", wantErr: true},
		{name: "minor suffix", version: APIVersion + ".1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAPIVersion(tt.version)
			if tt.wantErr {
				if !errors.Is(err, ErrUnsupportedAPIVersion) {
					t.Fatalf("expected ErrUnsupportedAPIVersion, got %v", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestValidateNames(t *testing.T) {
	valid := []string{
		testPluginName,
		"geoip_2",
		"a",
		"z" + "12345678901234567890123456789012345678901234567890123456789012",
	}

	for _, name := range valid {
		t.Run("valid module "+name, func(t *testing.T) {
			if err := ValidateModuleName(name); err != nil {
				t.Fatalf("expected valid module name, got %v", err)
			}
		})

		t.Run("valid component "+name, func(t *testing.T) {
			if err := ValidateComponentName(name); err != nil {
				t.Fatalf("expected valid component name, got %v", err)
			}
		})
	}

	invalid := []string{
		"",
		"GeoIP",
		"geo-ip",
		"geoip.public",
		"_geoip",
		"geo ip",
		"a" + "123456789012345678901234567890123456789012345678901234567890123",
	}

	for _, name := range invalid {
		t.Run("invalid module "+name, func(t *testing.T) {
			err := ValidateModuleName(name)
			if !errors.Is(err, ErrInvalidName) {
				t.Fatalf("expected ErrInvalidName, got %v", err)
			}
		})
	}
}

func TestValidateDebugModuleName(t *testing.T) {
	valid := []string{
		"batch",
		"lookup_2",
		"a",
	}

	for _, name := range valid {
		t.Run("valid "+name, func(t *testing.T) {
			if err := ValidateDebugModuleName(name); err != nil {
				t.Fatalf("ValidateDebugModuleName() error = %v", err)
			}
		})
	}

	invalid := []string{
		"",
		"Batch",
		"batch-log",
		"all",
		"none",
		"plugin",
		"auth",
		"policy",
	}

	for _, name := range invalid {
		t.Run("invalid "+name, func(t *testing.T) {
			err := ValidateDebugModuleName(name)
			if !errors.Is(err, ErrInvalidName) {
				t.Fatalf("ValidateDebugModuleName() error = %v, want ErrInvalidName", err)
			}
		})
	}
}

func TestValidatePluginDebugSelector(t *testing.T) {
	valid := []string{
		"plugin",
		"plugin.clickhouse",
		"plugin.clickhouse.batch",
	}

	for _, selector := range valid {
		t.Run("valid "+selector, func(t *testing.T) {
			if err := ValidatePluginDebugSelector(selector); err != nil {
				t.Fatalf("ValidatePluginDebugSelector() error = %v", err)
			}
		})
	}

	invalid := []string{
		"plugin.",
		"plugin.ClickHouse",
		"plugin.clickhouse.batch.extra",
		"plugin.clickhouse.all",
		"debug.clickhouse",
	}

	for _, selector := range invalid {
		t.Run("invalid "+selector, func(t *testing.T) {
			err := ValidatePluginDebugSelector(selector)
			if !errors.Is(err, ErrInvalidName) {
				t.Fatalf("ValidatePluginDebugSelector() error = %v, want ErrInvalidName", err)
			}
		})
	}
}

func TestValidateQualifiedComponentName(t *testing.T) {
	if err := ValidateQualifiedComponentName("geoip.environment"); err != nil {
		t.Fatalf("expected valid qualified name, got %v", err)
	}

	qualified, err := QualifiedComponentName("geoip", "environment")
	if err != nil {
		t.Fatalf("expected joined name, got %v", err)
	}

	if qualified != "geoip.environment" {
		t.Fatalf("expected geoip.environment, got %q", qualified)
	}

	invalid := []string{
		"environment",
		"geoip.",
		".environment",
		"geoip.environment.extra",
		"GeoIP.environment",
		"geoip.Environment",
	}

	for _, name := range invalid {
		t.Run(name, func(t *testing.T) {
			err := ValidateQualifiedComponentName(name)
			if !errors.Is(err, ErrInvalidName) {
				t.Fatalf("expected ErrInvalidName, got %v", err)
			}
		})
	}
}

func TestPluginPolicyAttributeID(t *testing.T) {
	attributeID, err := PluginPolicyAttributeID("environment", "geoip", "matched")
	if err != nil {
		t.Fatalf("PluginPolicyAttributeID() error = %v", err)
	}

	if attributeID != "plugin.environment.geoip.matched" {
		t.Fatalf("PluginPolicyAttributeID() = %q, want plugin.environment.geoip.matched", attributeID)
	}

	if _, err := PluginPolicyAttributeID("Environment", "geoip", "matched"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("PluginPolicyAttributeID() error = %v, want ErrInvalidName", err)
	}
}

func TestPublicPolicyFactLogField(t *testing.T) {
	field, err := PublicPolicyFactLogField("geoip", "matched", true)
	if err != nil {
		t.Fatalf("PublicPolicyFactLogField() error = %v", err)
	}

	if field.Key != "policy_fact_geoip_matched" || field.Value != true {
		t.Fatalf("PublicPolicyFactLogField() = %#v, want public geoip marker", field)
	}

	if _, err := PublicPolicyFactLogField("geoip", "Bad", true); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("PublicPolicyFactLogField() error = %v, want ErrInvalidName", err)
	}
}

func TestValidateBackendAttributeName(t *testing.T) {
	valid := []string{
		"account",
		"mailPrimaryAddress",
		"Proxy-Host",
		"ldap.attribute_1",
	}

	for _, name := range valid {
		t.Run("valid "+name, func(t *testing.T) {
			if err := ValidateBackendAttributeName(name); err != nil {
				t.Fatalf("expected valid backend attribute name, got %v", err)
			}
		})
	}

	invalid := []string{
		"",
		"mail primary",
		"mail\nprimary",
		string(rune(0x7f)),
	}

	for _, name := range invalid {
		t.Run("invalid "+name, func(t *testing.T) {
			err := ValidateBackendAttributeName(name)
			if !errors.Is(err, ErrInvalidName) {
				t.Fatalf("expected ErrInvalidName, got %v", err)
			}
		})
	}
}

func TestValidateMetadata(t *testing.T) {
	valid := Metadata{
		Name:       testPluginName,
		Version:    testPluginVersion,
		APIVersion: APIVersion,
	}

	if err := ValidateMetadata(valid); err != nil {
		t.Fatalf("expected valid metadata, got %v", err)
	}

	tests := []struct {
		name     string
		metadata Metadata
	}{
		{name: "api version", metadata: Metadata{Name: testPluginName, Version: testPluginVersion, APIVersion: "nauthilus.plugin.v2"}},
		{name: "name", metadata: Metadata{Name: "", Version: testPluginVersion, APIVersion: APIVersion}},
		{name: "version", metadata: Metadata{Name: testPluginName, Version: "", APIVersion: APIVersion}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMetadata(tt.metadata)
			if !errors.Is(err, ErrInvalidMetadata) {
				t.Fatalf("expected ErrInvalidMetadata, got %v", err)
			}
		})
	}
}

func TestSecretContractIsClosureOnly(t *testing.T) {
	secret := reflect.TypeFor[Secret]()

	if _, ok := secret.MethodByName("WithBytes"); !ok {
		t.Fatal("Secret must expose WithBytes")
	}

	if _, ok := secret.MethodByName("WithString"); ok {
		t.Fatal("Secret must not expose WithString")
	}
}

func TestBackendServerCandidateRef(t *testing.T) {
	candidate := BackendServerCandidate{
		Name:      "imap-a",
		Protocol:  "imap",
		Authority: "mail",
		Address:   "192.0.2.10",
		Port:      993,
		HAProxyV2: true,
		Alive:     true,
	}

	ref := candidate.Ref()
	if ref.Name != candidate.Name ||
		ref.Protocol != candidate.Protocol ||
		ref.Authority != candidate.Authority ||
		ref.Address != candidate.Address ||
		ref.Port != "993" {
		t.Fatalf("Ref() = %#v, want candidate reference", ref)
	}
}
