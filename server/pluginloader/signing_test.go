package pluginloader

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
)

func TestParsePluginSigningPrivateKeyAcceptsSeedAndPrivateKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate plugin signing key: %v", err)
	}

	testCases := []struct {
		name  string
		value []byte
	}{
		{name: "seed", value: privateKey.Seed()},
		{name: "private key", value: privateKey},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			parsed, err := ParsePluginSigningPrivateKey([]byte(base64.StdEncoding.EncodeToString(testCase.value)))
			if err != nil {
				t.Fatalf("ParsePluginSigningPrivateKey() error = %v", err)
			}

			if !parsed.Equal(privateKey) {
				t.Fatal("ParsePluginSigningPrivateKey() did not return the original private key")
			}
		})
	}
}

func TestFormatMinisignSignatureVerifiesWithLoader(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, []byte(testPluginContent))
	publicKey, privateKey, keyID := generatePluginSigningKey(t)

	publicKeyText, err := FormatPluginPublicKey(publicKey, keyID, "test plugin key")
	if err != nil {
		t.Fatalf("FormatPluginPublicKey() error = %v", err)
	}

	publicKeyPath := writePluginArtifact(t, pluginDir, "build.pub", publicKeyText)

	signaturePath := filepath.Join(pluginDir, "geoip.so.minisig")
	if err := WriteMinisignSignatureFile(artifact, signaturePath, privateKey, keyID, "timestamp:1760000000\tfile:geoip.so\thashed"); err != nil {
		t.Fatalf("WriteMinisignSignatureFile() error = %v", err)
	}

	_, err = verifySignedModule(t, pluginDir, artifact, publicKeyPath, signaturePath, config.PluginSignatureFormatMinisign)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestFormatMinisignSignatureRejectsMultilineTrustedComment(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, []byte(testPluginContent))
	_, privateKey, keyID := generatePluginSigningKey(t)

	_, err := FormatMinisignSignature(artifact, privateKey, keyID, "line one\nline two")
	if err == nil {
		t.Fatal("FormatMinisignSignature() error = nil, want newline rejection")
	}
}

func TestFormatPluginPublicKeyRejectsInvalidKeyID(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate plugin signing key: %v", err)
	}

	_, err = FormatPluginPublicKey(publicKey, []byte{1, 2, 3}, "test key")
	if err == nil {
		t.Fatal("FormatPluginPublicKey() error = nil, want key id validation error")
	}
}

func TestWriteMinisignSignatureFileReportsWriteFailure(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, []byte(testPluginContent))
	_, privateKey, keyID := generatePluginSigningKey(t)
	signaturePath := filepath.Join(pluginDir, "missing", "geoip.so.minisig")

	err := WriteMinisignSignatureFile(artifact, signaturePath, privateKey, keyID, "timestamp:1760000000\tfile:geoip.so\thashed")
	if err == nil {
		t.Fatal("WriteMinisignSignatureFile() error = nil, want write failure")
	}

	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("WriteMinisignSignatureFile() error = %v, want os.ErrNotExist", err)
	}
}
