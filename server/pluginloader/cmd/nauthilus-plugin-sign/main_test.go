package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
)

const (
	testFlagArtifact       = "--artifact"
	testFlagComment        = "--comment"
	testFlagPrivateKeyFile = "--private-key-file"
	testSignerID           = "build_key"
)

func TestRunKeygenPrintsSecretAndPublicKey(t *testing.T) {
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	err := run([]string{commandKeygen, testFlagComment, "ci key"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run() error = %v, stderr=%s", err, stderr.String())
	}

	output := stdout.String()
	expectedSnippets := []string{
		"NAUTHILUS_PLUGIN_SIGNING_KEY_B64=",
		"NAUTHILUS_PLUGIN_SIGNING_KEY_ID=",
		"Public key:\n",
		"untrusted comment: ci key\n",
	}

	for _, expected := range expectedSnippets {
		if !strings.Contains(output, expected) {
			t.Fatalf("keygen output must contain %q, got:\n%s", expected, output)
		}
	}
}

func TestRunPublicKeyDerivesConfiguredPublicKey(t *testing.T) {
	pluginDir := t.TempDir()
	privateKeyPath := writePrivateKeyFixture(t, pluginDir)

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	err := run([]string{commandPublicKey, testFlagPrivateKeyFile, privateKeyPath, testFlagComment, "release key"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run() error = %v, stderr=%s", err, stderr.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "NAUTHILUS_PLUGIN_SIGNING_KEY_ID=") {
		t.Fatalf("public-key output must include key id, got:\n%s", output)
	}

	if !strings.Contains(output, "untrusted comment: release key\n") {
		t.Fatalf("public-key output must include public key text, got:\n%s", output)
	}
}

func TestRunSignWritesSignatureAcceptedByVerifier(t *testing.T) {
	pluginDir := t.TempDir()
	privateKeyPath := writePrivateKeyFixture(t, pluginDir)
	artifact := filepath.Join(pluginDir, "geoip.so")
	signature := filepath.Join(pluginDir, "geoip.so.minisig")

	if err := os.WriteFile(artifact, []byte("geoip plugin"), 0o600); err != nil {
		t.Fatalf("write artifact fixture: %v", err)
	}

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	err := run([]string{
		commandSign,
		testFlagArtifact, artifact,
		"--signature", signature,
		testFlagPrivateKeyFile, privateKeyPath,
		"--trusted-comment", "timestamp:1760000000\tfile:geoip.so\thashed",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run() error = %v, stderr=%s", err, stderr.String())
	}

	publicKeyPath := writePublicKeyForPrivateKey(t, pluginDir, privateKeyPath)

	_, err = pluginloader.NewVerifier().Verify(&config.PluginsSection{
		AllowedDirs:        []string{pluginDir},
		VerificationPolicy: config.PluginVerificationPolicySignatureRequired,
		Trust: config.PluginTrustSection{
			Signers: []config.PluginTrustSigner{
				{
					ID:            testSignerID,
					Format:        config.PluginSignatureFormatMinisign,
					PublicKeyFile: publicKeyPath,
				},
			},
		},
		Modules: []config.PluginModule{
			{
				Name:      "geoip",
				Path:      artifact,
				Signature: config.PluginSignatureFormatMinisign + ":" + signature,
				Signer:    testSignerID,
			},
		},
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestRunSignRequiresPrivateKeyFile(t *testing.T) {
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	err := run([]string{commandSign, testFlagArtifact, "geoip.so"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run() error = nil, want missing private key failure")
	}
}

// writePrivateKeyFixture stores a base64 seed that matches the CLI secret format.
func writePrivateKeyFixture(t *testing.T, root string) string {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key fixture: %v", err)
	}

	path := filepath.Join(root, "plugin-signing-key.b64")

	content := []byte(base64.StdEncoding.EncodeToString(privateKey.Seed()))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write private key fixture: %v", err)
	}

	return path
}

// writePublicKeyForPrivateKey writes the verifier public key for a CLI private key fixture.
func writePublicKeyForPrivateKey(t *testing.T, root string, privateKeyPath string) string {
	t.Helper()

	raw, err := os.ReadFile(privateKeyPath)
	if err != nil {
		t.Fatalf("read private key fixture: %v", err)
	}

	privateKey, err := pluginloader.ParsePluginSigningPrivateKey(raw)
	if err != nil {
		t.Fatalf("parse private key fixture: %v", err)
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)

	keyID, err := pluginloader.DefaultPluginSigningKeyID(publicKey)
	if err != nil {
		t.Fatalf("derive key id fixture: %v", err)
	}

	publicKeyText, err := pluginloader.FormatPluginPublicKey(publicKey, keyID, "release key")
	if err != nil {
		t.Fatalf("format public key fixture: %v", err)
	}

	path := filepath.Join(root, "build.pub")
	if err := os.WriteFile(path, publicKeyText, 0o600); err != nil {
		t.Fatalf("write public key fixture: %v", err)
	}

	return path
}
