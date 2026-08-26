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

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
)

const (
	testPluginArtifactName = "geoip.so"
	testPluginModuleName   = "geoip"
	testPluginSignerID     = "build_key"
	testPluginContent      = "geoip plugin"
)

func TestVerifierRequiresExplicitArtifactReaderForConfiguredModules(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, []byte(testPluginContent))

	_, err := NewVerifier().Verify(&config.PluginsSection{
		AllowedDirs:        []string{pluginDir},
		VerificationPolicy: config.PluginVerificationPolicyOff,
		Modules: []config.PluginModule{{
			Name: testPluginModuleName,
			Path: artifact,
		}},
	})
	if !errors.Is(err, ErrArtifactReaderRequired) {
		t.Fatalf("Verify() error = %v, want ErrArtifactReaderRequired", err)
	}
}

// newFilesystemVerifier gives standalone verifier tests an explicit mutable-file authority.
func newFilesystemVerifier(options ...VerifierOption) Verifier {
	options = append([]VerifierOption{WithArtifactReader(os.ReadFile)}, options...)

	return NewVerifier(options...)
}

func TestVerifier_VerifiesChecksumSuccess(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, []byte(testPluginContent))

	verified, err := newFilesystemVerifier().Verify(&config.PluginsSection{
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

	_, err := newFilesystemVerifier().Verify(&config.PluginsSection{
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

	_, err := newFilesystemVerifier().Verify(&config.PluginsSection{
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

			_, err := newFilesystemVerifier().Verify(&config.PluginsSection{
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

// TestGenerationVerifierUsesOneArtifactSnapshot keeps every check on one immutable byte identity.
func TestGenerationVerifierUsesOneArtifactSnapshot(t *testing.T) {
	pluginDir := t.TempDir()
	firstContent := []byte("native plugin identity A")
	secondContent := []byte("native plugin identity B")
	secondArtifact := writePluginArtifact(t, pluginDir, "second.so", secondContent)
	keyPath, signature := writeMinisignFixture(t, pluginDir, secondArtifact)
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, firstContent)
	reader := &sequenceArtifactReader{target: artifact, contents: [][]byte{firstContent, secondContent}}
	verifier := NewVerifier(WithArtifactReader(reader.ReadFile))

	_, err := verifySignedModuleWithVerifier(
		t,
		verifier,
		pluginDir,
		artifact,
		keyPath,
		signature,
		config.PluginSignatureFormatMinisign,
	)
	if !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Fatalf("Verify() error = %v, want ErrSignatureVerificationFailed", err)
	}

	if reader.reads != 1 {
		t.Fatalf("artifact snapshot reads = %d, want 1", reader.reads)
	}
}

func TestSealedOptionalPluginAbsenceCannotLoadArtifactAppearingLater(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := filepath.Join(pluginDir, testPluginArtifactName)

	snapshot, err := config.CaptureArtifactSnapshot(config.ArtifactSnapshotSpec{
		OptionalPaths: []string{artifact},
	})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	t.Cleanup(snapshot.Release)

	if err = os.WriteFile(artifact, []byte("appeared after seal"), 0o600); err != nil {
		t.Fatalf("write late optional plugin: %v", err)
	}

	verified, err := NewVerifier(WithArtifactReader(snapshot.ReadFile)).Verify(&config.PluginsSection{
		AllowedDirs:        []string{pluginDir},
		VerificationPolicy: config.PluginVerificationPolicyOff,
		Modules: []config.PluginModule{{
			Name: testPluginModuleName, Path: artifact, Optional: true,
		}},
	})
	if err != nil {
		t.Fatalf("Verify(optional absent) error = %v", err)
	}

	if len(verified) != 1 || !errors.Is(verified[0].VerificationError, config.ErrArtifactNotCaptured) {
		t.Fatalf("verified optional absence = %#v, want captured failure", verified)
	}

	state, err := NewLoader(
		WithOpener(fakeOpener{}),
		WithLoaderArtifactReader(snapshot.ReadFile),
	).Load(verified)
	if err != nil {
		t.Fatalf("Load(optional absent) error = %v", err)
	}

	instances := state.Instances()
	if len(instances) != 1 || instances[0].Status != ModuleStatusFailed || !instances[0].Optional {
		t.Fatalf("optional absent instance = %#v, want deterministic failed optional state", instances)
	}
}

func TestSealedPluginVerificationAndStagingUseCapturedBytesAfterMutation(t *testing.T) {
	pluginDir := t.TempDir()
	captured := []byte("captured native plugin bytes")
	artifact := writePluginArtifact(t, pluginDir, testPluginArtifactName, captured)

	snapshot, err := config.CaptureArtifactSnapshot(config.ArtifactSnapshotSpec{Paths: []string{artifact}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	t.Cleanup(snapshot.Release)

	if err = os.WriteFile(artifact, []byte("mutated live plugin bytes"), 0o600); err != nil {
		t.Fatalf("mutate plugin after seal: %v", err)
	}

	verified, err := NewVerifier(WithArtifactReader(snapshot.ReadFile)).Verify(&config.PluginsSection{
		AllowedDirs:        []string{pluginDir},
		VerificationPolicy: config.PluginVerificationPolicyChecksumRequired,
		Modules: []config.PluginModule{{
			Name: testPluginModuleName, Path: artifact, Checksum: checksumForBytes(captured),
		}},
	})
	if err != nil {
		t.Fatalf("Verify(sealed bytes) error = %v", err)
	}

	opener := &replacementDuringOpenOpener{
		originalPath: artifact, verifiedContent: captured,
		handle: fakeHandle{symbol: func() (pluginapi.Plugin, error) {
			return fakePlugin{metadata: validLoaderMetadata()}, nil
		}},
	}

	state, err := NewLoader(
		WithOpener(opener),
		WithLoaderArtifactReader(snapshot.ReadFile),
	).Load(verified)
	if err != nil {
		t.Fatalf("Load(sealed bytes) error = %v", err)
	}

	if instances := state.Instances(); len(instances) != 1 || !instances[0].IsRegistered() {
		t.Fatalf("sealed plugin instances = %#v, want one registered instance", instances)
	}
}

type sequenceArtifactReader struct {
	target   string
	contents [][]byte
	reads    int
}

// ReadFile returns one detached artifact identity per verifier read.
func (r *sequenceArtifactReader) ReadFile(path string) ([]byte, error) {
	if path != r.target {
		return os.ReadFile(path)
	}
	if r.reads >= len(r.contents) {
		return nil, errors.New("unexpected artifact snapshot read")
	}

	content := append([]byte(nil), r.contents[r.reads]...)
	r.reads++

	return content, nil
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

	return verifySignedModuleWithVerifier(
		t,
		newFilesystemVerifier(),
		pluginDir,
		artifact,
		keyPath,
		signature,
		format,
	)
}

// verifySignedModuleWithVerifier runs one signed-module fixture through a configured verifier.
func verifySignedModuleWithVerifier(
	t *testing.T,
	verifier Verifier,
	pluginDir string,
	artifact string,
	keyPath string,
	signature string,
	format string,
) ([]VerifiedModule, error) {
	t.Helper()

	return verifier.Verify(&config.PluginsSection{
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
