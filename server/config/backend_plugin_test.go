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
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
)

const backendPluginTestLDAP = "ldap"

func TestBackendSet_PluginSelector(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		wantBackend definitions.Backend
		wantName    string
		wantErr     bool
	}{
		{
			name:        "qualified plugin backend",
			value:       "plugin(customer.passdb)",
			wantBackend: definitions.BackendPlugin,
			wantName:    "customer.passdb",
		},
		{
			name:    "unqualified plugin backend",
			value:   "plugin(passdb)",
			wantErr: true,
		},
		{
			name:    "bare plugin backend",
			value:   "plugin",
			wantErr: true,
		},
		{
			name:        "ldap remains compatible",
			value:       backendPluginTestLDAP,
			wantBackend: definitions.BackendLDAP,
			wantName:    definitions.DefaultBackendName,
		},
		{
			name:        "named lua remains compatible",
			value:       "lua(customer)",
			wantBackend: definitions.BackendLua,
			wantName:    "customer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertBackendSelector(t, tt.value, tt.wantBackend, tt.wantName, tt.wantErr)
		})
	}
}

// assertBackendSelector verifies one backend selector parse case.
func assertBackendSelector(
	t *testing.T,
	value string,
	wantBackend definitions.Backend,
	wantName string,
	wantErr bool,
) {
	t.Helper()

	backend := &Backend{}

	err := backend.Set(value)
	if wantErr {
		if err == nil {
			t.Fatalf("Set(%q) error = nil, want error", value)
		}

		return
	}

	if err != nil {
		t.Fatalf("Set(%q) error = %v", value, err)
	}

	if backend.Get() != wantBackend {
		t.Fatalf("Backend.Get() = %s, want %s", backend.Get(), wantBackend)
	}

	if backend.GetName() != wantName {
		t.Fatalf("Backend.GetName() = %q, want %q", backend.GetName(), wantName)
	}
}
