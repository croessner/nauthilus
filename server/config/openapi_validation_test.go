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

package config

import (
	"strings"
	"testing"
)

func TestOpenAPIValidation_DefaultsToDisabled(t *testing.T) {
	settings := &FileSettings{}

	if settings.GetServer().GetOpenAPIValidation().IsEnabled() {
		t.Fatal("OpenAPI runtime validation must be disabled by default")
	}
}

func TestApplyRuntimeSection_MaterializesOpenAPIValidation(t *testing.T) {
	settings := &FileSettings{
		Runtime: &RuntimeSection{
			Servers: RuntimeServersSection{
				HTTP: RuntimeHTTPServerSection{
					OpenAPIValidation: OpenAPIValidation{
						Operations: []string{OpenAPIValidationOperationFlushUserCache},
						Enabled:    true,
						Enforce:    true,
					},
				},
			},
		},
	}

	server := settings.materializeServerSection()
	validation := server.GetOpenAPIValidation()

	if !validation.IsEnabled() {
		t.Fatal("materialized OpenAPI runtime validation should be enabled")
	}

	if got := validation.GetOperations(); len(got) != 1 || got[0] != OpenAPIValidationOperationFlushUserCache {
		t.Fatalf("operations = %v, want [%s]", got, OpenAPIValidationOperationFlushUserCache)
	}
}

func TestValidateOpenAPIValidation_RequiresExplicitEnforceMode(t *testing.T) {
	settings := &FileSettings{
		Server: &ServerSection{
			OpenAPIValidation: OpenAPIValidation{
				Operations: []string{OpenAPIValidationOperationFlushUserCache},
				Enabled:    true,
			},
		},
	}

	err := settings.validateOpenAPIValidation()
	if err == nil {
		t.Fatal("validateOpenAPIValidation() error = nil, want enforce requirement")
	}

	if !strings.Contains(err.Error(), "enforce") {
		t.Fatalf("validateOpenAPIValidation() error = %v, want enforce requirement", err)
	}
}

func TestValidateOpenAPIValidation_RejectsAuthOperations(t *testing.T) {
	settings := &FileSettings{
		Server: &ServerSection{
			OpenAPIValidation: OpenAPIValidation{
				Operations: []string{"postJSONAuth"},
				Enabled:    true,
				Enforce:    true,
			},
		},
	}

	err := settings.validateOpenAPIValidation()
	if err == nil {
		t.Fatal("validateOpenAPIValidation() error = nil, want unsupported operation")
	}

	if !strings.Contains(err.Error(), "postJSONAuth") {
		t.Fatalf("validateOpenAPIValidation() error = %v, want operation name", err)
	}
}

func TestValidateOpenAPIValidation_AcceptsPilotOperations(t *testing.T) {
	settings := &FileSettings{
		Server: &ServerSection{
			OpenAPIValidation: OpenAPIValidation{
				Operations: []string{
					OpenAPIValidationOperationFlushUserCache,
					OpenAPIValidationOperationEnqueueUserCacheFlush,
					OpenAPIValidationOperationListFilteredBruteForceEntries,
					OpenAPIValidationOperationFlushBruteForceRule,
				},
				Enabled: true,
				Enforce: true,
			},
		},
	}

	if err := settings.validateOpenAPIValidation(); err != nil {
		t.Fatalf("validateOpenAPIValidation() error = %v, want nil", err)
	}
}
