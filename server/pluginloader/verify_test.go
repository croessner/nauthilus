package pluginloader

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
)

const (
	testPluginArtifactName = "geoip.so"
	testPluginModuleName   = "geoip"
	testPluginSignerID     = "build_key"
	testPluginContent      = "geoip plugin"
)

func TestVerifier_VerifiesChecksumSuccess(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, []byte(testPluginContent))

	verified, err := NewVerifier().Verify(&config.PluginsSection{
		AllowedDirs:        []string{pluginDir},
		VerificationPolicy: config.PluginVerificationPolicyChecksumRequired,
		Modules: []config.PluginModule{
			{
				Name:     testPluginModuleName,
				Path:     artifact,
				Checksum: checksumForBytes([]byte(testPluginContent)),
			},
		},
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if len(verified) != 1 {
		t.Fatalf("Verify() verified %d modules, want 1", len(verified))
	}

	expectedPath, err := filepath.EvalSymlinks(artifact)
	if err != nil {
		t.Fatalf("resolve expected artifact path: %v", err)
	}

	if verified[0].ArtifactPath != expectedPath {
		t.Fatalf("Verify() artifact path = %q, want %q", verified[0].ArtifactPath, expectedPath)
	}
}

func TestVerifier_RejectsChecksumMismatch(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, []byte(testPluginContent))

	_, err := NewVerifier().Verify(&config.PluginsSection{
		AllowedDirs:        []string{pluginDir},
		VerificationPolicy: config.PluginVerificationPolicyChecksumRequired,
		Modules: []config.PluginModule{
			{
				Name:     testPluginModuleName,
				Path:     artifact,
				Checksum: checksumForBytes([]byte("other plugin")),
			},
		},
	})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("Verify() error = %v, want ErrChecksumMismatch", err)
	}
}

func TestVerifier_RejectsArtifactOutsideAllowedDirs(t *testing.T) {
	pluginDir := t.TempDir()
	otherDir := t.TempDir()
	target := writePluginArtifact(t, otherDir, testPluginArtifactName, []byte(testPluginContent))
	artifact := filepath.Join(pluginDir, testPluginArtifactName)

	if err := os.Symlink(target, artifact); err != nil {
		t.Fatalf("create plugin artifact symlink: %v", err)
	}

	_, err := NewVerifier().Verify(&config.PluginsSection{
		AllowedDirs:        []string{pluginDir},
		VerificationPolicy: config.PluginVerificationPolicyOff,
		Modules: []config.PluginModule{
			{
				Name: testPluginModuleName,
				Path: artifact,
			},
		},
	})
	if !errors.Is(err, ErrArtifactOutsideAllowedDirs) {
		t.Fatalf("Verify() error = %v, want ErrArtifactOutsideAllowedDirs", err)
	}
}

func TestVerifier_RejectsMissingRequiredVerificationMetadata(t *testing.T) {
	testCases := []struct {
		name   string
		policy string
	}{
		{name: "checksum", policy: config.PluginVerificationPolicyChecksumRequired},
		{name: "signature", policy: config.PluginVerificationPolicySignatureRequired},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			pluginDir := t.TempDir()
			artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, []byte(testPluginContent))

			_, err := NewVerifier().Verify(&config.PluginsSection{
				AllowedDirs:        []string{pluginDir},
				VerificationPolicy: testCase.policy,
				Modules: []config.PluginModule{
					{
						Name: testPluginModuleName,
						Path: artifact,
					},
				},
			})
			if err == nil || !errors.Is(err, config.ErrPluginConfigInvalid) {
				t.Fatalf("Verify() error = %v, want plugin config validation error", err)
			}
		})
	}
}

func TestVerifier_VerifiesMinisignDetachedSignature(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, []byte(testPluginContent))
	keyPath, signature := writeMinisignFixture(t, pluginDir, artifact)

	verified, err := verifySignedModule(t, pluginDir, artifact, keyPath, signature, config.PluginSignatureFormatMinisign)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if len(verified) != 1 {
		t.Fatalf("Verify() verified %d modules, want 1", len(verified))
	}

	if verified[0].Signer == nil || verified[0].Signer.ID != testPluginSignerID {
		t.Fatalf("Verify() signer = %#v, want %q", verified[0].Signer, testPluginSignerID)
	}

	if verified[0].SignaturePath == "" {
		t.Fatal("Verify() did not report canonical signature path")
	}
}

func TestVerifier_VerifiesSignifyDetachedSignature(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, []byte(testPluginContent))
	keyPath, signature := writeSignifyFixture(t, pluginDir, artifact)

	_, err := verifySignedModule(t, pluginDir, artifact, keyPath, signature, config.PluginSignatureFormatSignify)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifier_RejectsInvalidDetachedSignature(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, []byte(testPluginContent))
	otherArtifact := writePluginArtifact(t, pluginDir, "other.so", []byte("different content"))
	keyPath, signature := writeMinisignFixture(t, pluginDir, otherArtifact)

	_, err := verifySignedModule(t, pluginDir, artifact, keyPath, signature, config.PluginSignatureFormatMinisign)
	if !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Fatalf("Verify() error = %v, want ErrSignatureVerificationFailed", err)
	}
}

// verifySignedModule runs the verifier with one trusted signer and one signed module.
func verifySignedModule(
	t *testing.T,
	pluginDir string,
	artifact string,
	keyPath string,
	signature string,
	format string,
) ([]VerifiedModule, error) {
	t.Helper()

	return NewVerifier().Verify(&config.PluginsSection{
		AllowedDirs:        []string{pluginDir},
		VerificationPolicy: config.PluginVerificationPolicySignatureRequired,
		Trust: config.PluginTrustSection{
			Signers: []config.PluginTrustSigner{
				{
					ID:            testPluginSignerID,
					Format:        format,
					PublicKeyFile: keyPath,
				},
			},
		},
		Modules: []config.PluginModule{
			{
				Name:      testPluginModuleName,
				Path:      artifact,
				Signature: format + ":" + signature,
				Signer:    testPluginSignerID,
			},
		},
	})
}

// writePluginArtifact stores a fixture artifact under a temporary plugin directory.
func writePluginArtifact(t *testing.T, root string, name string, content []byte) string {
	t.Helper()

	path := filepath.Join(root, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write plugin artifact %s: %v", path, err)
	}

	return path
}

// writeMinisignFixture creates a trusted public key and minisign signature for one artifact.
func writeMinisignFixture(t *testing.T, root string, artifact string) (string, string) {
	t.Helper()

	publicKey, privateKey, keyID := generatePluginSigningKey(t)
	trustedComment := "timestamp:1760000000\tfile:geoip.so\thashed"

	publicKeyText, err := FormatPluginPublicKey(publicKey, keyID, "minisign public key")
	if err != nil {
		t.Fatalf("format plugin public key: %v", err)
	}

	keyPath := writePluginArtifact(t, root, "build.pub", publicKeyText)

	signaturePath := filepath.Join(root, "geoip.so.minisig")
	if err := WriteMinisignSignatureFile(artifact, signaturePath, privateKey, keyID, trustedComment); err != nil {
		t.Fatalf("write minisign fixture: %v", err)
	}

	return keyPath, signaturePath
}

// writeSignifyFixture creates a trusted public key and signify-style signature for one artifact.
func writeSignifyFixture(t *testing.T, root string, artifact string) (string, string) {
	t.Helper()

	publicKey, privateKey, keyID := generatePluginSigningKey(t)

	content, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatalf("read artifact fixture: %v", err)
	}

	signatureBlob := detachedSignatureBlob("Ed", keyID, ed25519.Sign(privateKey, content))

	publicKeyText, err := FormatPluginPublicKey(publicKey, keyID, "signify public key")
	if err != nil {
		t.Fatalf("format plugin public key: %v", err)
	}

	keyPath := writePluginArtifact(t, root, "build.pub", publicKeyText)
	signaturePath := writePluginArtifact(t, root, "geoip.so.sig", []byte(
		"untrusted comment: signify signature\n"+
			base64ForTest(signatureBlob)+"\n",
	))

	return keyPath, signaturePath
}

// generatePluginSigningKey creates an Ed25519 key pair and deterministic plugin key id.
func generatePluginSigningKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, []byte) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate plugin signing key: %v", err)
	}

	keyID, err := DefaultPluginSigningKeyID(publicKey)
	if err != nil {
		t.Fatalf("derive plugin signing key id: %v", err)
	}

	return publicKey, privateKey, keyID
}

// base64ForTest encodes binary signature payloads for fixture files.
func base64ForTest(payload []byte) string {
	return base64.StdEncoding.EncodeToString(payload)
}

// checksumForBytes returns the configuration checksum reference for fixture content.
func checksumForBytes(content []byte) string {
	sum := sha256.Sum256(content)

	return "sha256:" + hex.EncodeToString(sum[:])
}
