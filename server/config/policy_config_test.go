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

type removedPolicyConfigCase struct {
	settings map[string]any
	name     string
	wantPath string
}

var removedPolicyConfigCases = []removedPolicyConfigCase{
	{
		name:     "old root",
		settings: map[string]any{"auth": map[string]any{"policy": map[string]any{"mode": "enforce"}}},
		wantPath: "auth.policy",
	},
	{
		name: "mixed roots",
		settings: map[string]any{
			"auth":   map[string]any{"policy": map[string]any{"mode": "enforce"}},
			"policy": map[string]any{"api": map[string]any{"enabled": true}},
		},
		wantPath: "auth.policy",
	},
	{
		name: "legacy stage alias",
		settings: map[string]any{"policy": map[string]any{"namespaces": map[string]any{
			"authn": map[string]any{"providers": map[string]any{
				"risk": map[string]any{"kind": "lua", "stage": "pre_auth"},
			}},
		}}},
		wantPath: "policy.namespaces.authn.providers.risk.stage",
	},
	{
		name: "legacy config ref alias",
		settings: map[string]any{"policy": map[string]any{"namespaces": map[string]any{
			"authn": map[string]any{"providers": map[string]any{
				"risk": map[string]any{"kind": "lua", "config_ref": "legacy"},
			}},
		}}},
		wantPath: "policy.namespaces.authn.providers.risk.config_ref",
	},
	{
		name: "unqualified standard auth",
		settings: map[string]any{"policy": map[string]any{"targets": []any{map[string]any{
			"namespace":      "authn",
			"action":         "authenticate",
			"schema":         "authn/authenticate/v1",
			"mode":           "enforce",
			"default_policy": "standard_auth",
		}}}},
		wantPath: "policy.targets[0].default_policy",
	},
	{
		name: "legacy top-level Lua environment sources",
		settings: map[string]any{"lua": map[string]any{
			"environment_sources": []any{map[string]any{"name": "legacy", "script_path": "legacy.lua"}},
		}},
		wantPath: "lua",
	},
	{
		name: "legacy top-level Lua subject sources",
		settings: map[string]any{"lua": map[string]any{
			"subject_sources": []any{map[string]any{"name": "legacy", "script_path": "legacy.lua"}},
		}},
		wantPath: "lua",
	},
	{
		name: "legacy top-level Lua actions",
		settings: map[string]any{"lua": map[string]any{
			"actions": []any{map[string]any{"type": "lua", "name": "legacy", "script_path": "legacy.lua"}},
		}},
		wantPath: "lua",
	},
}

func TestPolicyConfigDecodesNormalizesAndDumps(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	SetConfigDumpPrintSensitiveValues(false)

	viper.Set("policy.api.enabled", true)
	viper.Set("policy.api.http.enabled", true)
	viper.Set("policy.api.grpc.enabled", true)
	viper.Set("policy.api.grpc.require_mtls", true)
	viper.Set("policy.api.limits.max_facts", 64)
	viper.Set("policy.api.clients", []map[string]any{
		{
			"principal":            "Policy.Client",
			"authentication_kinds": []string{"oidc_bearer", "basic"},
			"authentication": map[string]any{
				"basic": map[string]any{
					"username": "Policy.User",
					"password": "policy-basic-secret",
				},
			},
			"targets": []map[string]any{
				{"namespace": "authn", "actions": []string{"authenticate"}},
			},
			"allowed_schemas": []string{"authn/authenticate/v1"},
			"diagnostics":     true,
			"require_mtls":    true,
		},
	})

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("HandleFile() error = %v", err)
	}

	policyConfig := cfg.GetPolicy()
	if !policyConfig.API.Enabled {
		t.Fatal("GetPolicy().API.Enabled = false, want true")
	}

	if got, want := policyConfig.API.Limits.MaxFacts, 64; got != want {
		t.Fatalf("GetPolicy().API.Limits.MaxFacts = %d, want %d", got, want)
	}

	if got, want := policyConfig.API.Limits.MaxRequestBytes, 1<<20; got != want {
		t.Fatalf("GetPolicy().API.Limits.MaxRequestBytes = %d, want %d", got, want)
	}

	if !policyConfig.API.HTTP.Enabled || !policyConfig.API.GRPC.Enabled || !policyConfig.API.GRPC.RequireMTLS {
		t.Fatal("GetPolicy().API must enable HTTP and mTLS-required gRPC")
	}

	if len(policyConfig.API.Clients) != 1 || policyConfig.API.Clients[0].Authentication.Basic == nil {
		t.Fatal("GetPolicy().API.Clients must contain one dedicated Basic-capable profile")
	}

	assertPolicyConfigDumps(t)
}

// assertPolicyConfigDumps verifies both canonical policy dump modes use the new root only.
func assertPolicyConfigDumps(t *testing.T) {
	t.Helper()

	defaultDump, err := RenderDefaultConfigDump()
	if err != nil {
		t.Fatalf("RenderDefaultConfigDump() error = %v", err)
	}

	assertPolicyDumpContainsAll(t, defaultDump, []string{
		`policy.api.enabled = false`,
		`policy.api.http.enabled = false`,
		`policy.api.grpc.enabled = false`,
		`policy.api.grpc.require_mtls = false`,
		`policy.api.clients = []`,
		`policy.api.limits.max_request_bytes = 1048576`,
		`policy.api.limits.max_facts = 512`,
		`policy.api.limits.per_client_concurrency = 8`,
		`policy.api.limits.per_client_requests_per_second = 25`,
	})

	if strings.Contains(defaultDump, "auth.policy") {
		t.Fatalf("RenderDefaultConfigDump() contains removed auth.policy root: %q", defaultDump)
	}

	nonDefaultDump, err := RenderNonDefaultConfigDump(viper.AllSettings())
	if err != nil {
		t.Fatalf("RenderNonDefaultConfigDump() error = %v", err)
	}

	assertPolicyDumpContainsAll(t, nonDefaultDump, []string{
		`policy.api.enabled = true`,
		`policy.api.http.enabled = true`,
		`policy.api.grpc.enabled = true`,
		`policy.api.grpc.require_mtls = true`,
		`policy.api.limits.max_facts = 64`,
		`policy.api.clients = [`,
		`"principal": "Policy.Client"`,
		`"authentication_kinds": ["oidc_bearer", "basic"]`,
		`"username": "Policy.User"`,
		`"password": "***REDACTED***"`,
		`"namespace": "authn"`,
		`"actions": ["authenticate"]`,
		`"allowed_schemas": ["authn/authenticate/v1"]`,
		`"diagnostics": true`,
		`"require_mtls": true`,
	})

	if strings.Contains(nonDefaultDump, "policy-basic-secret") {
		t.Fatal("RenderNonDefaultConfigDump() exposed a Policy-Basic secret")
	}
}

// assertPolicyDumpContainsAll verifies a compact set of required canonical dump lines.
func assertPolicyDumpContainsAll(t *testing.T, dump string, expected []string) {
	t.Helper()

	for _, line := range expected {
		if !strings.Contains(dump, line) {
			t.Fatalf("config dump missing %q in %q", line, dump)
		}
	}
}

func TestPolicyConfigRejectsRemovedShapes(t *testing.T) {
	for _, test := range removedPolicyConfigCases {
		t.Run(test.name, func(t *testing.T) {
			reader := viper.New()
			if err := reader.MergeConfigMap(test.settings); err != nil {
				t.Fatalf("MergeConfigMap() error = %v", err)
			}

			err := (&FileSettings{}).handleFile(reader)
			if err == nil {
				t.Fatal("handleFile() error = nil, want hard-cut rejection")
			}

			if !strings.Contains(err.Error(), test.wantPath) {
				t.Fatalf("handleFile() error = %q, want path %q", err, test.wantPath)
			}
		})
	}
}
