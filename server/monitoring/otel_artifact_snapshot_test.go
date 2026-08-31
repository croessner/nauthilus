// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package monitoring

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/testing/testpki"
)

func TestOTLPHTTPOptionsUseSealedCAAfterLiveMutation(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, testpki.NewSelfSigned(t).CertificatePEM, 0o600); err != nil {
		t.Fatalf("write captured OTLP CA: %v", err)
	}

	configured := &config.FileSettings{Server: &config.ServerSection{}}

	configured.Server.Insights.Tracing = config.Tracing{
		Enabled:  true,
		Exporter: "otlphttp",
		TLS: config.TLS{
			Enabled: true,
			CAFile:  caPath,
		},
	}
	if _, err := config.EnsureArtifactSnapshot(configured); err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	if err := os.WriteFile(caPath, []byte("mutated invalid CA\n"), 0o600); err != nil {
		t.Fatalf("mutate OTLP CA: %v", err)
	}

	options, err := otlpHTTPOptions(configured, configured.Server.Insights.GetTracing())
	if err != nil {
		t.Fatalf("otlpHTTPOptions() error = %v", err)
	}

	if len(options) == 0 {
		t.Fatal("otlpHTTPOptions() returned no TLS option for captured CA")
	}
}
