package config

import (
	"reflect"
	"testing"
)

func TestUnknownConfigParameters_RootAndNested(t *testing.T) {
	settings := map[string]any{
		"developer_mode": false,
		"identity": map[string]any{
			"frontend": map[string]any{
				"security_headers": map[string]any{
					"unknown_leaf": true,
				},
			},
		},
		"top_level": "x",
	}

	got, err := unknownConfigParameters(settings)
	if err != nil {
		t.Fatalf("unknownConfigParameters() error = %v", err)
	}

	want := []string{
		"identity.frontend.security_headers.unknown_leaf",
		"top_level",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknownConfigParameters() = %v, want %v", got, want)
	}
}

func TestUnknownConfigParameters_CustomScopes(t *testing.T) {
	settings := map[string]any{
		"identity": map[string]any{
			"oidc": map[string]any{
				"custom_scopes": []any{
					map[string]any{
						"description_de":    "Deutsch",
						"description_en-US": "English",
						"foo":               "bar",
					},
					map[string]any{
						"nested": map[string]any{"x": 1},
					},
				},
			},
		},
	}

	got, err := unknownConfigParameters(settings)
	if err != nil {
		t.Fatalf("unknownConfigParameters() error = %v", err)
	}

	want := []string{
		"identity.oidc.custom_scopes[0].foo",
		"identity.oidc.custom_scopes[1].nested.x",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknownConfigParameters() = %v, want %v", got, want)
	}
}

func TestUnknownConfigParameters_ClientCustomScopes(t *testing.T) {
	settings := map[string]any{
		"identity": map[string]any{
			"oidc": map[string]any{
				"clients": []any{
					map[string]any{
						"client_id": "client-1",
						"custom_scopes": []any{
							map[string]any{
								"description_de": "Deutsch",
								"foo":            "bar",
							},
							map[string]any{
								"nested": map[string]any{"x": 1},
							},
						},
					},
				},
			},
		},
	}

	got, err := unknownConfigParameters(settings)
	if err != nil {
		t.Fatalf("unknownConfigParameters() error = %v", err)
	}

	want := []string{
		"identity.oidc.clients[0].custom_scopes[0].foo",
		"identity.oidc.clients[0].custom_scopes[1].nested.x",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknownConfigParameters() = %v, want %v", got, want)
	}
}

func TestUnknownConfigParameters_CyclicMap(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle

	got, err := unknownConfigParameters(map[string]any{"cycle": cycle})
	if err != nil {
		t.Fatalf("unknownConfigParameters() error = %v", err)
	}

	want := []string{"cycle.self"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknownConfigParameters() = %v, want %v", got, want)
	}
}

func TestUnknownConfigParameters_RootExtensionsIgnored(t *testing.T) {
	settings := map[string]any{
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
	}

	got, err := unknownConfigParameters(settings)
	if err != nil {
		t.Fatalf("unknownConfigParameters() error = %v", err)
	}

	want := []string{"top_level"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknownConfigParameters() = %v, want %v", got, want)
	}
}
