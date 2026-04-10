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
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSetDefaultSecuritySettings_CORS verifies that centralized CORS defaults
// are populated when the section is omitted.
func TestSetDefaultSecuritySettings_CORS(t *testing.T) {
	cfg := &FileSettings{
		Server: &ServerSection{},
	}

	err := cfg.setDefaultSecuritySettings()
	assert.NoError(t, err)

	cors := cfg.Server.CORS
	if assert.NotNil(t, cors.Enabled) {
		assert.False(t, *cors.Enabled)
	}

	if assert.Len(t, cors.Policies, 1) {
		policy := cors.Policies[0]
		assert.Equal(t, defaultCORSPolicyName, policy.Name)
		if assert.NotNil(t, policy.Enabled) {
			assert.True(t, *policy.Enabled)
		}
		assert.Equal(t, defaultCORSPathPrefixes, policy.PathPrefixes)
		assert.Equal(t, defaultCORSAllowMethods, policy.AllowMethods)
		assert.Equal(t, defaultCORSAllowHeaders, policy.AllowHeaders)
		assert.Equal(t, defaultCORSMaxAge, policy.MaxAge)
	}
}

// TestSetDefaultSecuritySettings_PreservesCustomCORS verifies that explicitly
// configured CORS values are preserved by default-setting logic.
func TestSetDefaultSecuritySettings_PreservesCustomCORS(t *testing.T) {
	enabled := true
	allowCredentials := true

	cfg := &FileSettings{
		Server: &ServerSection{
			CORS: CORS{
				Enabled: &enabled,
				Policies: []CORSPolicy{
					{
						Name:             "api",
						Enabled:          &enabled,
						PathPrefixes:     []string{"/api/v1/mfa"},
						AllowOrigins:     []string{"https://oc.roessner.cloud"},
						AllowMethods:     []string{"GET"},
						AllowHeaders:     []string{"Authorization"},
						ExposeHeaders:    []string{"X-Request-ID"},
						AllowCredentials: &allowCredentials,
						MaxAge:           3600,
					},
				},
			},
		},
	}

	err := cfg.setDefaultSecuritySettings()
	assert.NoError(t, err)

	cors := cfg.Server.CORS
	if assert.NotNil(t, cors.Enabled) {
		assert.True(t, *cors.Enabled)
	}

	if assert.Len(t, cors.Policies, 1) {
		policy := cors.Policies[0]
		assert.Equal(t, "api", policy.Name)
		if assert.NotNil(t, policy.Enabled) {
			assert.True(t, *policy.Enabled)
		}
		assert.Equal(t, []string{"/api/v1/mfa"}, policy.PathPrefixes)
		assert.Equal(t, []string{"https://oc.roessner.cloud"}, policy.AllowOrigins)
		assert.Equal(t, []string{"GET"}, policy.AllowMethods)
		assert.Equal(t, []string{"Authorization"}, policy.AllowHeaders)
		assert.Equal(t, []string{"X-Request-ID"}, policy.ExposeHeaders)
		if assert.NotNil(t, policy.AllowCredentials) {
			assert.True(t, *policy.AllowCredentials)
		}
		assert.EqualValues(t, 3600, policy.MaxAge)
	}
}
