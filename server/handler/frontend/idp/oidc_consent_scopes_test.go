package idp

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/stretchr/testify/assert"
)

func TestConsentScopeDescription_UsesClientCustomScopeOverride(t *testing.T) {
	oidcCfg := &config.OIDCConfig{
		CustomScopes: []config.Oauth2CustomScope{
			{
				Name:        "resource",
				Description: "Global resource description",
				Other: map[string]any{
					"description_de": "Globale Beschreibung",
				},
			},
		},
	}
	client := &config.OIDCClient{
		ClientID: "client-1",
		CustomScopes: []config.Oauth2CustomScope{
			{
				Name:        "resource",
				Description: "Client resource description",
				Other: map[string]any{
					"description_de": "Client Beschreibung",
				},
			},
		},
	}

	customScopes := oidcCfg.GetEffectiveCustomScopes(client)
	desc, ok := consentScopeDescription(nil, nil, nil, customScopes, "de-DE", "resource")
	assert.True(t, ok)
	assert.Equal(t, "Client Beschreibung", desc)
}

func TestConsentScopeDescription_UsesGlobalCustomScopeWhenClientDoesNotOverride(t *testing.T) {
	oidcCfg := &config.OIDCConfig{
		CustomScopes: []config.Oauth2CustomScope{
			{
				Name:        "resource",
				Description: "Global resource description",
				Other: map[string]any{
					"description_de": "Globale Beschreibung",
				},
			},
		},
	}
	client := &config.OIDCClient{
		ClientID: "client-1",
	}

	customScopes := oidcCfg.GetEffectiveCustomScopes(client)
	desc, ok := consentScopeDescription(nil, nil, nil, customScopes, "de-DE", "resource")
	assert.True(t, ok)
	assert.Equal(t, "Globale Beschreibung", desc)
}
