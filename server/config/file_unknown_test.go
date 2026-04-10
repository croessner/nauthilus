package config

import (
	"reflect"
	"testing"
)

func TestUnknownConfigParameters_RootAndNested(t *testing.T) {
	cfg := &FileSettings{
		Other: map[string]any{
			"developer_mode": false,
			"server.frontend": map[string]any{
				"security_headers": map[string]any{
					"unknown_leaf": true,
				},
			},
			"top_level": "x",
		},
	}

	got := cfg.unknownConfigParameters()
	want := []string{
		"server.frontend.security_headers.unknown_leaf",
		"top_level",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknownConfigParameters() = %v, want %v", got, want)
	}
}

func TestUnknownConfigParameters_CustomScopes(t *testing.T) {
	cfg := &FileSettings{
		IdP: &IdPSection{
			OIDC: OIDCConfig{
				CustomScopes: []Oauth2CustomScope{
					{
						Other: map[string]any{
							"description_de":    "Deutsch",
							"description_en-US": "English",
							"foo":               "bar",
						},
					},
					{
						Other: map[string]any{
							"nested": map[string]any{"x": 1},
						},
					},
				},
			},
		},
	}

	got := cfg.unknownConfigParameters()
	want := []string{
		"idp.oidc.custom_scopes[0].foo",
		"idp.oidc.custom_scopes[1].nested.x",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknownConfigParameters() = %v, want %v", got, want)
	}
}

func TestUnknownConfigParameters_CyclicMap(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle

	cfg := &FileSettings{
		Other: map[string]any{
			"cycle": cycle,
		},
	}

	got := cfg.unknownConfigParameters()
	want := []string{"cycle.self"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknownConfigParameters() = %v, want %v", got, want)
	}
}

func TestUnknownConfigParameters_RootExtensionsIgnored(t *testing.T) {
	cfg := &FileSettings{
		Other: map[string]any{
			"x-claim-email": map[string]any{
				"claim":     "email",
				"attribute": "mail;x-hidden",
				"type":      "string",
			},
			"x-scope-profile": map[string]any{
				"mappings": []any{
					map[string]any{"claim": "name", "attribute": "cn;x-hidden", "type": "string"},
				},
			},
			"top_level": "x",
		},
	}

	got := cfg.unknownConfigParameters()
	want := []string{"top_level"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknownConfigParameters() = %v, want %v", got, want)
	}
}
