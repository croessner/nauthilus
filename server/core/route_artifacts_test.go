// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/util/keygen"
	"github.com/gin-gonic/gin"
)

func TestPreparedRouteArtifactsKeepSealedFrontendTemplateAfterLiveMutation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	directory := t.TempDir()
	templatePath := filepath.Join(directory, "sealed.html")
	writeRouteArtifact(t, templatePath, []byte(`{{ define "sealed.html" }}sealed-template{{ end }}`))

	cfg := &config.FileSettings{Server: &config.ServerSection{Frontend: config.Frontend{
		Enabled: true, HTMLStaticContentPath: directory,
	}}}
	snapshot := captureRouteArtifacts(t, cfg)
	prepared := prepareRouteArtifacts(t, cfg, snapshot)

	writeRouteArtifact(t, templatePath, []byte(`{{ define "sealed.html" }}mutated-template{{ end }}`))

	composer := NewDefaultRouterComposer(HTTPDeps{
		Cfg: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), RouteArtifacts: prepared,
	})
	engine := composer.ComposeEngine()
	composer.RegisterRoutes(engine, nil, nil, func(router *gin.Engine) {
		router.GET("/sealed", func(ctx *gin.Context) {
			ctx.HTML(http.StatusOK, "sealed.html", nil)
		})
	}, nil)

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/sealed", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("GET /sealed status = %d, want %d", response.Code, http.StatusOK)
	}

	if got := response.Body.String(); got != "sealed-template" {
		t.Fatalf("GET /sealed body = %q, want captured template", got)
	}
}

func TestPrepareRouteArtifactsRejectsInvalidSealedFrontendTemplate(t *testing.T) {
	directory := t.TempDir()
	templatePath := filepath.Join(directory, "invalid.html")
	writeRouteArtifact(t, templatePath, []byte(`{{ define "invalid.html" }}{{`))

	cfg := &config.FileSettings{Server: &config.ServerSection{Frontend: config.Frontend{
		Enabled: true, HTMLStaticContentPath: directory,
	}}}
	snapshot := captureRouteArtifacts(t, cfg)

	if _, err := PrepareRouteArtifacts(cfg, snapshot); err == nil {
		t.Fatal("PrepareRouteArtifacts() error = nil, want invalid template rejection before startup commit")
	}
}

func TestPreparedRouteArtifactsKeepSealedHTTPIdentityAndTrustAfterLiveMutation(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	caPath := filepath.Join(directory, "clients.pem")

	capturedCert, capturedKey := generateRouteTLSKeyPair(t, "captured.example")
	mutatedCert, mutatedKey := generateRouteTLSKeyPair(t, "mutated.example")
	writeRouteArtifact(t, certPath, capturedCert)
	writeRouteArtifact(t, keyPath, capturedKey)
	writeRouteArtifact(t, caPath, capturedCert)

	cfg := &config.FileSettings{Server: &config.ServerSection{TLS: config.TLS{
		Enabled: true, Cert: certPath, Key: keyPath, CAFile: caPath,
	}}}
	snapshot := captureRouteArtifacts(t, cfg)
	prepared := prepareRouteArtifacts(t, cfg, snapshot)

	writeRouteArtifact(t, certPath, mutatedCert)
	writeRouteArtifact(t, keyPath, mutatedKey)
	writeRouteArtifact(t, caPath, mutatedCert)

	tlsConfig := NewDefaultTLSConfigurator(HTTPDeps{Cfg: cfg, RouteArtifacts: prepared}).Build()
	if tlsConfig == nil || len(tlsConfig.Certificates) != 1 {
		t.Fatalf("HTTP TLS certificates = %#v, want one sealed identity", tlsConfig)
	}

	capturedPair, err := tls.X509KeyPair(capturedCert, capturedKey)
	if err != nil {
		t.Fatalf("parse captured TLS key pair: %v", err)
	}

	if !bytes.Equal(tlsConfig.Certificates[0].Certificate[0], capturedPair.Certificate[0]) {
		t.Fatal("HTTP TLS identity came from live mutated files, want sealed certificate")
	}

	capturedLeaf, err := x509.ParseCertificate(capturedPair.Certificate[0])
	if err != nil {
		t.Fatalf("parse captured TLS certificate: %v", err)
	}

	if _, err = capturedLeaf.Verify(x509.VerifyOptions{
		Roots: tlsConfig.RootCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("sealed HTTP CA does not trust captured certificate: %v", err)
	}
}

func TestPrepareRouteArtifactsRejectsInvalidHTTPIdentityBeforeStartupCommit(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")

	writeRouteArtifact(t, certPath, []byte("not a certificate"))
	writeRouteArtifact(t, keyPath, []byte("not a private key"))

	cfg := &config.FileSettings{Server: &config.ServerSection{TLS: config.TLS{
		Enabled: true, Cert: certPath, Key: keyPath,
	}}}
	snapshot := captureRouteArtifacts(t, cfg)

	if _, err := PrepareRouteArtifacts(cfg, snapshot); err == nil {
		t.Fatal("PrepareRouteArtifacts() error = nil, want invalid HTTP identity rejection before startup commit")
	}
}

func TestPrepareRouteArtifactsRejectsInvalidListenerTrustBeforeStartupCommit(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	caPath := filepath.Join(directory, "clients.pem")
	cert, key := generateRouteTLSKeyPair(t, "listener.example")
	writeRouteArtifact(t, certPath, cert)
	writeRouteArtifact(t, keyPath, key)
	writeRouteArtifact(t, caPath, []byte("not a CA bundle"))

	for _, testCase := range []struct {
		name string
		cfg  *config.FileSettings
	}{
		{
			name: "HTTP client CA",
			cfg: &config.FileSettings{Server: &config.ServerSection{TLS: config.TLS{
				Enabled: true, Cert: certPath, Key: keyPath, CAFile: caPath,
			}}},
		},
		{
			name: "gRPC client CA",
			cfg: &config.FileSettings{
				Server: &config.ServerSection{},
				Runtime: &config.RuntimeSection{Servers: config.RuntimeServersSection{
					GRPC: config.RuntimeGRPCServersSection{Authority: config.RuntimeGRPCAuthServerSection{
						TLS: config.RuntimeGRPCTLSSection{
							Enabled: true, Cert: certPath, Key: keyPath, ClientCA: caPath,
						},
					}},
				}},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			snapshot := captureRouteArtifacts(t, testCase.cfg)
			if _, err := PrepareRouteArtifacts(testCase.cfg, snapshot); err == nil {
				t.Fatal("PrepareRouteArtifacts() error = nil, want invalid listener trust rejection")
			}
		})
	}
}

func TestPreparedRouteArtifactsKeepSealedSecurityTxtFilesAfterLiveMutation(t *testing.T) {
	directory := t.TempDir()
	policyPath := filepath.Join(directory, "policy.md")
	keyPath := filepath.Join(directory, "security.asc")

	writeRouteArtifact(t, policyPath, []byte("captured policy\n"))
	writeRouteArtifact(t, keyPath, []byte("captured key\n"))

	cfg := &config.FileSettings{Server: &config.ServerSection{SecurityTxt: config.SecurityTxt{
		Enabled: true, PolicyFile: policyPath, EncryptionFile: keyPath,
	}}}
	snapshot := captureRouteArtifacts(t, cfg)
	prepared := prepareRouteArtifacts(t, cfg, snapshot)

	writeRouteArtifact(t, policyPath, []byte("mutated policy\n"))
	writeRouteArtifact(t, keyPath, []byte("mutated key\n"))

	for path, want := range map[string]string{policyPath: "captured policy\n", keyPath: "captured key\n"} {
		content, err := prepared.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%q) error = %v", path, err)
		}

		if string(content) != want {
			t.Fatalf("ReadFile(%q) = %q, want sealed bytes %q", path, content, want)
		}
	}
}

// captureRouteArtifacts seals the exact test-owned route inputs.
func captureRouteArtifacts(t *testing.T, cfg config.File) *config.ArtifactSnapshot {
	t.Helper()

	snapshot, err := config.CaptureArtifactSnapshot(config.ProductionArtifactSnapshotSpec(cfg))
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	return snapshot
}

// prepareRouteArtifacts parses one immutable route artifact set for a test.
func prepareRouteArtifacts(t *testing.T, cfg config.File, snapshot *config.ArtifactSnapshot) *RouteArtifacts {
	t.Helper()

	prepared, err := PrepareRouteArtifacts(cfg, snapshot)
	if err != nil {
		t.Fatalf("PrepareRouteArtifacts() error = %v", err)
	}

	return prepared
}

// generateRouteTLSKeyPair creates one test-owned PEM identity.
func generateRouteTLSKeyPair(t *testing.T, commonName string) ([]byte, []byte) {
	t.Helper()

	cert, key, err := keygen.GenerateSelfSignedCert(commonName, 2048, 1)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert() error = %v", err)
	}

	return []byte(cert), []byte(key)
}

// writeRouteArtifact replaces one test-owned route input.
func writeRouteArtifact(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write route artifact %q: %v", path, err)
	}
}
