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

func TestSecurityHeaderComposer_ComposeContentSecurityPolicy_StringValue(t *testing.T) {
	composer := NewSecurityHeaderComposer()

	value, changed, err := composer.ComposeContentSecurityPolicy("default-src 'none'", nil)

	if !assert.NoError(t, err) {
		return
	}

	assert.True(t, changed)
	assert.Equal(t, "default-src 'none'", value)
}

func TestSecurityHeaderComposer_ComposeContentSecurityPolicy_DirectiveMap(t *testing.T) {
	composer := NewSecurityHeaderComposer()

	value, changed, err := composer.ComposeContentSecurityPolicy(
		map[string][]string{
			"connect-src": {"'self'", "https://api.example.test"},
			"frame-src":   {"'self'", "https:", "https://widgets.example.test"},
		},
		[]string{"https://idp.example.test"},
	)

	if !assert.NoError(t, err) {
		return
	}

	assert.True(t, changed)
	assert.Equal(
		t,
		"default-src 'self'; script-src 'self' 'nonce-{{nonce}}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.example.test; frame-src 'self' https: https://widgets.example.test; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://idp.example.test",
		value,
	)
	assert.NotContains(t, value, "form-action 'self' https: https://idp.example.test")
}

func TestSecurityHeaderComposer_ComposeContentSecurityPolicy_DirectiveMap_NoOptionalKeepsDefaultHTTPS(t *testing.T) {
	composer := NewSecurityHeaderComposer()

	value, changed, err := composer.ComposeContentSecurityPolicy(
		map[string][]string{
			"connect-src": {"'self'", "https://api.example.test"},
		},
		nil,
	)

	if !assert.NoError(t, err) {
		return
	}

	assert.True(t, changed)
	assert.Contains(t, value, "form-action 'self' https:")
}

func TestSecurityHeaderComposer_ComposeContentSecurityPolicy_DirectiveMap_ExplicitFormActionKeepsHTTPS(t *testing.T) {
	composer := NewSecurityHeaderComposer()

	value, changed, err := composer.ComposeContentSecurityPolicy(
		map[string][]string{
			"form-action": {"'self'", "https:"},
		},
		[]string{"https://idp.example.test"},
	)

	if !assert.NoError(t, err) {
		return
	}

	assert.True(t, changed)
	assert.Contains(t, value, "form-action 'self' https: https://idp.example.test")
}

func TestSecurityHeaderComposer_ComposePermissionsPolicy_FeatureMap(t *testing.T) {
	composer := NewSecurityHeaderComposer()

	value, changed, err := composer.ComposePermissionsPolicy(map[string]string{
		"microphone": "(self)",
		"fullscreen": "(self)",
	})

	if !assert.NoError(t, err) {
		return
	}

	assert.True(t, changed)
	assert.Equal(t, "geolocation=(), microphone=(self), camera=(), payment=(), usb=(), fullscreen=(self)", value)
}

func TestSecurityHeaderComposer_ComposeStrictTransportSecurity_Object(t *testing.T) {
	composer := NewSecurityHeaderComposer()

	maxAge := "63072000"
	includeSubDomains := false
	preload := true

	value, changed, err := composer.ComposeStrictTransportSecurity(strictTransportSecurityObject{
		maxAge:            &maxAge,
		includeSubDomains: &includeSubDomains,
		preload:           &preload,
		extraTokens:       []string{"example-token"},
	})

	if !assert.NoError(t, err) {
		return
	}

	assert.True(t, changed)
	assert.Equal(t, "max-age=63072000; preload; example-token", value)
}

func TestProcessContentSecurityPolicyValue_Object(t *testing.T) {
	value, err := processContentSecurityPolicyValue(map[string]any{
		"directives": map[string]any{
			"connect-src": []any{"'self'", "https://api.example.test"},
		},
		"form_action_optional_uris": []any{"https://idp.example.test"},
	})

	if !assert.NoError(t, err) {
		return
	}

	typed, ok := value.(ContentSecurityPolicyValue)
	if !assert.True(t, ok) {
		return
	}

	headers := FrontendSecurityHeaders{
		ContentSecurityPolicy: typed,
	}

	assert.Equal(
		t,
		"default-src 'self'; script-src 'self' 'nonce-{{nonce}}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.example.test; frame-src 'self' https:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://idp.example.test",
		headers.GetContentSecurityPolicy(),
	)
	assert.NotContains(t, headers.GetContentSecurityPolicy(), "form-action 'self' https: https://idp.example.test")
}

func TestProcessContentSecurityPolicyValue_ObjectTopLevelDirectives(t *testing.T) {
	value, err := processContentSecurityPolicyValue(map[string]any{
		"connect-src": []any{"'self'", "https://api.example.test"},
		"form-action": []any{"'self'", "https:"},
	})

	if !assert.NoError(t, err) {
		return
	}

	typed, ok := value.(ContentSecurityPolicyValue)
	if !assert.True(t, ok) {
		return
	}

	headers := FrontendSecurityHeaders{
		ContentSecurityPolicy: typed,
	}

	assert.Contains(t, headers.GetContentSecurityPolicy(), "connect-src 'self' https://api.example.test")
	assert.Contains(t, headers.GetContentSecurityPolicy(), "form-action 'self' https:")
}

func TestProcessPermissionsPolicyValue_Object(t *testing.T) {
	value, err := processPermissionsPolicyValue(map[string]any{
		"features": map[string]any{
			"microphone": "(self)",
		},
		"fullscreen": "(self)",
	})

	if !assert.NoError(t, err) {
		return
	}

	typed, ok := value.(PermissionsPolicyValue)
	if !assert.True(t, ok) {
		return
	}

	headers := FrontendSecurityHeaders{
		PermissionsPolicy: typed,
	}

	assert.Equal(t, "geolocation=(), microphone=(self), camera=(), payment=(), usb=(), fullscreen=(self)", headers.GetPermissionsPolicy())
}

func TestProcessStrictTransportSecurityValue_Object(t *testing.T) {
	value, err := processStrictTransportSecurityValue(map[string]any{
		"max_age":            63072000,
		"include_subdomains": false,
		"preload":            true,
		"extra_tokens":       []any{"example-token"},
	})

	if !assert.NoError(t, err) {
		return
	}

	typed, ok := value.(StrictTransportSecurityValue)
	if !assert.True(t, ok) {
		return
	}

	headers := FrontendSecurityHeaders{
		StrictTransportSecurity: typed,
	}

	assert.Equal(t, "max-age=63072000; preload; example-token", headers.GetStrictTransportSecurity())
}

func TestProcessContentSecurityPolicyValue_InvalidObjectKey(t *testing.T) {
	_, err := processContentSecurityPolicyValue(map[string]any{
		"form_action_optional_uri": []any{"https://idp.example.test"},
	})

	if !assert.Error(t, err) {
		return
	}

	assert.Contains(t, err.Error(), "unknown")
}

func TestProcessContentSecurityPolicyValue_UnsupportedDirective(t *testing.T) {
	_, err := processContentSecurityPolicyValue(map[string]any{
		"manifest-src": []any{"'self'"},
	})

	if !assert.Error(t, err) {
		return
	}

	assert.Contains(t, err.Error(), "supported directives")
	assert.Contains(t, err.Error(), "manifest-src")
}

func TestFrontendSecurityHeaders_ValidateComposedValues_InvalidPermissionsPolicy(t *testing.T) {
	headers := FrontendSecurityHeaders{
		PermissionsPolicy: NewPermissionsPolicyValueFromPartials([]string{"microphone"}),
	}

	err := headers.ValidateComposedValues()

	if !assert.Error(t, err) {
		return
	}

	assert.Contains(t, err.Error(), securityHeadersPermissionsKey)
}
