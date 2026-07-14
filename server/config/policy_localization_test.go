// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestPolicyLocalizationCatalogsDecodeValidateAndDump(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setPolicyConfigTestStorage()
	viper.Set("auth.policy.localization.catalogs", []any{
		map[string]any{
			"namespace": "rns-auth",
			"language":  "de",
			"entries": map[string]any{
				"auth.policy.rns.account_disabled": "Konto gesperrt.",
			},
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("HandleFile() error = %v", err)
	}

	catalogs := cfg.GetPolicyLocalizationCatalogs()
	if len(catalogs) != 1 || catalogs[0].Language != "de" || catalogs[0].Namespace != "rns-auth" {
		t.Fatalf("catalogs = %#v, want decoded rns-auth German catalog", catalogs)
	}

	catalogs[0].Entries["auth.policy.rns.account_disabled"] = "mutated"
	if got := cfg.GetPolicyLocalizationCatalogs()[0].Entries["auth.policy.rns.account_disabled"]; got != "Konto gesperrt." {
		t.Fatalf("catalog mutation changed config state: %q", got)
	}

	dump, err := RenderNonDefaultConfigDump(viper.AllSettings())
	if err != nil {
		t.Fatalf("RenderNonDefaultConfigDump() error = %v", err)
	}

	for _, expected := range []string{
		`auth.policy.localization.catalogs[0].namespace = "rns-auth"`,
		`auth.policy.localization.catalogs[0].language = "de"`,
		`auth.policy.localization.catalogs[0].entries = {"auth.policy.rns.account_disabled": "Konto gesperrt."}`,
	} {
		if !strings.Contains(dump, expected) {
			t.Fatalf("config dump missing %q in %q", expected, dump)
		}
	}
}

func TestPolicyLocalizationCatalogsRejectInvalidDeclarations(t *testing.T) {
	tests := []struct {
		name       string
		language   string
		key        string
		wantPath   string
		wantDetail string
	}{
		{
			name:       "invalid language",
			language:   "not a language",
			key:        "auth.policy.rns.account_disabled",
			wantPath:   "auth.policy.localization.catalogs[0].language",
			wantDetail: "BCP 47",
		},
		{
			name:       "blank message key",
			language:   "de",
			key:        " ",
			wantPath:   "auth.policy.localization.catalogs[0].entries",
			wantDetail: "message key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)

			setPolicyConfigTestStorage()
			viper.Set("auth.policy.localization.catalogs", []any{
				map[string]any{
					"namespace": "rns-auth",
					"language":  test.language,
					"entries":   map[string]any{test.key: "message"},
				},
			})

			err := (&FileSettings{}).HandleFile()
			if err == nil {
				t.Fatal("HandleFile() error = nil, want validation failure")
			}

			if !strings.Contains(err.Error(), test.wantPath) || !strings.Contains(err.Error(), test.wantDetail) {
				t.Fatalf("HandleFile() error = %q, want path %q and detail %q", err, test.wantPath, test.wantDetail)
			}
		})
	}
}
