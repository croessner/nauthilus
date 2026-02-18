package config

import "testing"

func TestDefaultPatchEngine_Apply(t *testing.T) {
	engine := DefaultPatchEngine{}

	settings := map[string]any{
		"ldap": map[string]any{
			"search": []any{
				map[string]any{
					"protocol": "imap",
				},
			},
			"config": map[string]any{
				"bind_dn": "old",
				"bind_pw": "secret",
			},
		},
	}

	patches := []PatchOperation{
		{
			Op:   patchOpAdd,
			Path: "ldap.search",
			Value: map[string]any{
				"protocol": "smtp",
			},
		},
		{
			Op:    patchOpReplace,
			Path:  "ldap.config.bind_dn",
			Value: "new",
		},
		{
			Op:    patchOpRemove,
			Path:  "ldap.config",
			Value: "bind_pw",
		},
	}

	if err := engine.Apply(settings, patches); err != nil {
		t.Fatalf("apply patches: %v", err)
	}

	ldap, ok := settings["ldap"].(map[string]any)
	if !ok {
		t.Fatalf("expected ldap map, got %T", settings["ldap"])
	}

	config, ok := ldap["config"].(map[string]any)
	if !ok {
		t.Fatalf("expected ldap.config map, got %T", ldap["config"])
	}

	if config["bind_dn"] != "new" {
		t.Fatalf("expected bind_dn new, got %v", config["bind_dn"])
	}

	if _, ok := config["bind_pw"]; ok {
		t.Fatal("expected bind_pw to be removed")
	}

	search, ok := ldap["search"].([]any)
	if !ok {
		t.Fatalf("expected ldap.search slice, got %T", ldap["search"])
	}

	if len(search) != 2 {
		t.Fatalf("expected 2 ldap.search entries, got %d", len(search))
	}
}
