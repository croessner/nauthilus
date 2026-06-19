package config

import (
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/secret"
)

const (
	testMetricsEndpointUsername = "prometheus"
	testMetricsEndpointPassword = "metrics-password"
	metricsEndpointUsernamePath = "observability.metrics.endpoint_auth.basic.username"
	metricsEndpointPasswordPath = "observability.metrics.endpoint_auth.basic.password"
)

func TestFileSettingsMaterializesMetricsEndpointAuth(t *testing.T) {
	cfg := &FileSettings{
		Observability: &ObservabilitySection{
			Metrics: ObservabilityMetrics{
				EndpointAuth: MetricsEndpointAuth{
					Basic: BasicAuth{
						Enabled:  true,
						Username: testMetricsEndpointUsername,
						Password: secret.New(testMetricsEndpointPassword),
					},
				},
			},
		},
	}

	basic := cfg.GetServer().GetMetricsEndpointAuth().GetBasicAuth()
	if !basic.IsEnabled() {
		t.Fatal("metrics endpoint basic auth should be enabled")
	}

	if basic.GetUsername() != testMetricsEndpointUsername {
		t.Fatalf("username = %q, want %q", basic.GetUsername(), testMetricsEndpointUsername)
	}

	password := ""

	basic.GetPassword().WithString(func(value string) {
		password = value
	})

	if password != testMetricsEndpointPassword {
		t.Fatalf("password = %q, want %q", password, testMetricsEndpointPassword)
	}
}

func TestConfigPathFromStructNamespace_UsesMetricsEndpointAuthTags(t *testing.T) {
	schemaIndex, err := getConfigSchemaIndex()
	if err != nil {
		t.Fatalf("getConfigSchemaIndex() error = %v", err)
	}

	got := schemaIndex.configPathFromStructNamespace("FileSettings.Observability.Metrics.EndpointAuth.Basic.Username")
	want := metricsEndpointUsernamePath

	if got != want {
		t.Fatalf("configPathFromStructNamespace() = %q, want %q", got, want)
	}
}

func TestValidateMetricsEndpointAuthRequiresCredentialsWhenEnabled(t *testing.T) {
	cfg := &FileSettings{
		Observability: &ObservabilitySection{
			Metrics: ObservabilityMetrics{
				EndpointAuth: MetricsEndpointAuth{
					Basic: BasicAuth{Enabled: true},
				},
			},
		},
	}

	err := cfg.validateMetricsEndpointAuth()
	if err == nil {
		t.Fatal("validateMetricsEndpointAuth() error = nil, want missing credentials error")
	}

	got := err.Error()
	for _, want := range []string{
		metricsEndpointUsernamePath,
		metricsEndpointPasswordPath,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("validateMetricsEndpointAuth() error = %q, want substring %q", got, want)
		}
	}
}
