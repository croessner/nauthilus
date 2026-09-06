package main

import (
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
)

// runtimePluginAdmissionMap exposes authorization metadata without Policy code or authentication material.
func runtimePluginAdmissionMap(policy policyconfig.PolicyConfig) map[string]any {
	api := policy.API
	clients := make([]any, 0, len(api.Clients))
	for _, profile := range api.Clients {
		targets := make([]any, 0, len(profile.Targets))
		for _, grant := range profile.Targets {
			for _, action := range grant.Actions {
				targets = append(targets, grant.Namespace+"/"+action)
			}
		}

		schemas := make([]any, 0, len(profile.AllowedSchemas))
		for _, schema := range profile.AllowedSchemas {
			schemas = append(schemas, schema)
		}

		clients = append(clients, map[string]any{
			"principal": profile.Principal, "targets": targets, "schemas": schemas, "diagnostics": profile.Diagnostics,
			"max_concurrency":     runtimePluginAdmissionLimit(profile.MaxConcurrency, api.Limits.PerClientConcurrency),
			"requests_per_second": runtimePluginAdmissionLimit(profile.RequestsPerSecond, api.Limits.PerClientRequestsPerSecond),
		})
	}

	targets := make([]any, 0, len(policy.Targets))
	for _, target := range policy.Targets {
		targets = append(targets, map[string]any{"target": target.Namespace + "/" + target.Action, "schema": target.Schema, "mode": target.Mode, "no_match": target.NoMatch})
	}

	return map[string]any{"enabled": api.Enabled, "clients": clients, "targets": targets}
}

// runtimePluginAdmissionLimit shares the transport's authoritative limit resolver and fails closed on invalid profiles.
func runtimePluginAdmissionLimit(profile, global int) int {
	value, err := admission.ResolveLimit(profile, global)
	if err != nil {
		return 0
	}

	return value
}
