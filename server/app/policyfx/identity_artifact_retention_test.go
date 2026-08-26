// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

func TestProductionCoordinatorRetainsGenerationOnIdentityAuthorityArtifactMutation(t *testing.T) {
	tests := []struct {
		candidate func(*testing.T) (*config.FileSettings, string)
		name      string
	}{
		{name: "OIDC signing key", candidate: sealedOIDCSigningCandidate},
		{name: "remote authority static token", candidate: sealedRemoteTokenCandidate},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configured, artifactPath := test.candidate(t)
			if _, err := config.EnsureArtifactSnapshot(configured); err != nil {
				t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
			}

			baseline, err := NewRestartBaseline(configured)
			if err != nil {
				t.Fatalf("NewRestartBaseline() error = %v", err)
			}
			defer baseline.Close()

			store := policyruntime.NewGenerationStore()

			coordinator := newRestartBaselineCoordinator(t, store, configured, baseline)
			if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 1}); err != nil {
				t.Fatalf("Apply(G1) error = %v", err)
			}

			active := store.Active()
			activeConfig := active.Config()
			activeCatalog := active.TargetCatalog()
			activeApplication := active.Application()
			activeBindings := active.Bindings()

			if err = os.WriteFile(artifactPath, []byte("mutated after G1 commit\n"), 0o600); err != nil {
				t.Fatalf("mutate sealed artifact: %v", err)
			}

			err = coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 2})
			if !errors.Is(err, pluginruntime.ErrRestartRequired) {
				t.Fatalf("Apply(mutated G2) error = %v, want ErrRestartRequired", err)
			}

			assertRestartBaselineRetainedGeneration(
				t, store, active, activeConfig, activeCatalog, activeApplication, activeBindings,
			)
		})
	}
}

// sealedOIDCSigningCandidate returns one candidate with an exact file-backed OIDC key.
func sealedOIDCSigningCandidate(t *testing.T) (*config.FileSettings, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate OIDC signing key: %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "oidc-signing.pem")

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err = os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write OIDC signing key: %v", err)
	}

	return &config.FileSettings{IDP: &config.IDPSection{OIDC: config.OIDCConfig{
		SigningKeys: []config.OIDCKey{{ID: "sealed", KeyFile: keyPath, Active: true}},
	}}}, keyPath
}

// sealedRemoteTokenCandidate returns one candidate with an exact file-backed authority token.
func sealedRemoteTokenCandidate(t *testing.T) (*config.FileSettings, string) {
	t.Helper()

	tokenPath := filepath.Join(t.TempDir(), "authority-token")
	if err := os.WriteFile(tokenPath, []byte("opaque-authority-token\n"), 0o600); err != nil {
		t.Fatalf("write authority token: %v", err)
	}

	return &config.FileSettings{Runtime: &config.RuntimeSection{
		Clients: config.RuntimeClientsSection{GRPC: config.RuntimeGRPCClientsSection{
			NauthilusAuthorities: map[string]*config.NauthilusAuthorityClientSection{
				"edge": {
					Address: "127.0.0.1:9444",
					CallerAuth: config.AuthorityCallerAuthSection{OIDCBearer: config.AuthorityOIDCBearerSection{
						StaticTokenFile: tokenPath,
					}},
				},
			},
		}},
	}}, tokenPath
}
