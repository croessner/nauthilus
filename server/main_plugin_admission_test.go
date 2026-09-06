package main

import (
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/secret"
	"testing"
)

// TestPluginAdmissionProjectionExcludesCredentials retains only authorization metadata for startup cross-checks.
func TestPluginAdmissionProjectionExcludesCredentials(t *testing.T) {
	api := policyconfig.APIConfig{Enabled: true, Limits: policyconfig.APILimitsConfig{PerClientConcurrency: 4, PerClientRequestsPerSecond: 20},
		Clients: []policyconfig.ClientProfileConfig{{Principal: "Writer", MaxConcurrency: 2,
			Authentication: policyconfig.ClientAuthenticationConfig{Basic: &policyconfig.BasicAuthenticationConfig{Username: "private-user", Password: secret.New("private-password")}},
			Targets:        []policyconfig.ClientTargetConfig{{Namespace: "workflow", Actions: []string{"submit"}}}, AllowedSchemas: []string{"workflow/submit/v1"}}}}
	result := runtimePluginAdmissionMap(policyconfig.PolicyConfig{API: api})
	clients := result["clients"].([]any)

	client := clients[0].(map[string]any)
	if len(client) != 6 || client["principal"] != "Writer" || client["max_concurrency"] != 2 || client["requests_per_second"] != 20 {
		t.Fatalf("unexpected admission projection keys or limits")
	}

	if _, exists := client["authentication"]; exists {
		t.Fatal("credentials exposed")
	}

	cfg := loadRuntimePluginHostConfig(t)

	view, err := runtimePluginConfigMap(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if _, exists := view["policy_admission"]; !exists {
		t.Fatal("production host omits admission projection")
	}
}
