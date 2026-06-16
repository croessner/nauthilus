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
	secret := reflect.TypeOf((*Secret)(nil)).Elem()

	if _, ok := secret.MethodByName("WithBytes"); !ok {
		t.Fatal("Secret must expose WithBytes")
	}

	if _, ok := secret.MethodByName("WithString"); ok {
		t.Fatal("Secret must not expose WithString")
	}
}
