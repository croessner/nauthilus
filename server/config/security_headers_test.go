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

func TestSetDefaultFrontendSettings_SecurityHeaders(t *testing.T) {
	cfg := &FileSettings{
		Server: &ServerSection{},
	}

	err := cfg.setDefaultFrontendSettings()
	assert.NoError(t, err)

	headers := cfg.Server.Frontend.SecurityHeaders
	if assert.NotNil(t, headers.Enabled) {
		assert.True(t, *headers.Enabled)
	}
	assert.Contains(t, headers.ContentSecurityPolicy, "script-src 'self' 'nonce-{{nonce}}'")
	assert.Contains(t, headers.ContentSecurityPolicy, "style-src 'self' 'unsafe-inline'")
	assert.NotContains(t, headers.ContentSecurityPolicy, "style-src 'self' 'nonce-{{nonce}}'")
	assert.Contains(t, headers.ContentSecurityPolicy, "form-action 'self'")
	assert.Equal(t, "max-age=31536000; includeSubDomains", headers.StrictTransportSecurity)
	assert.Equal(t, "nosniff", headers.XContentTypeOptions)
	assert.Equal(t, "DENY", headers.XFrameOptions)
	assert.Equal(t, "no-referrer", headers.ReferrerPolicy)
	assert.Equal(t, "geolocation=(), microphone=(), camera=(), payment=(), usb=()", headers.PermissionsPolicy)
	assert.Equal(t, "same-origin", headers.CrossOriginOpenerPolicy)
	assert.Equal(t, "same-origin", headers.CrossOriginResourcePolicy)
	assert.Equal(t, "unsafe-none", headers.CrossOriginEmbedderPolicy)
	assert.Equal(t, "none", headers.XPermittedCrossDomainPolicies)
	assert.Equal(t, "off", headers.XDNSPrefetchControl)
}

func TestSetDefaultFrontendSettings_PreservesCustomSecurityHeaders(t *testing.T) {
	enabled := false
	cfg := &FileSettings{
		Server: &ServerSection{
			Frontend: Frontend{
				SecurityHeaders: FrontendSecurityHeaders{
					Enabled:                       &enabled,
					ContentSecurityPolicy:         "default-src 'none'",
					StrictTransportSecurity:       "max-age=100",
					XContentTypeOptions:           "custom",
					XFrameOptions:                 "SAMEORIGIN",
					ReferrerPolicy:                "origin",
					PermissionsPolicy:             "fullscreen=(self)",
					CrossOriginOpenerPolicy:       "same-origin-allow-popups",
					CrossOriginResourcePolicy:     "cross-origin",
					CrossOriginEmbedderPolicy:     "require-corp",
					XPermittedCrossDomainPolicies: "master-only",
					XDNSPrefetchControl:           "on",
				},
			},
		},
	}

	err := cfg.setDefaultFrontendSettings()
	assert.NoError(t, err)

	headers := cfg.Server.Frontend.SecurityHeaders
	if assert.NotNil(t, headers.Enabled) {
		assert.False(t, *headers.Enabled)
	}
	assert.Equal(t, "default-src 'none'", headers.ContentSecurityPolicy)
	assert.Equal(t, "max-age=100", headers.StrictTransportSecurity)
	assert.Equal(t, "custom", headers.XContentTypeOptions)
	assert.Equal(t, "SAMEORIGIN", headers.XFrameOptions)
	assert.Equal(t, "origin", headers.ReferrerPolicy)
	assert.Equal(t, "fullscreen=(self)", headers.PermissionsPolicy)
	assert.Equal(t, "same-origin-allow-popups", headers.CrossOriginOpenerPolicy)
	assert.Equal(t, "cross-origin", headers.CrossOriginResourcePolicy)
	assert.Equal(t, "require-corp", headers.CrossOriginEmbedderPolicy)
	assert.Equal(t, "master-only", headers.XPermittedCrossDomainPolicies)
	assert.Equal(t, "on", headers.XDNSPrefetchControl)
}
