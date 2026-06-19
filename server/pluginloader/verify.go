// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package pluginloader verifies native plugin artifacts before loading them.
package pluginloader

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"golang.org/x/crypto/blake2b"
)

var (
	// ErrArtifactOutsideAllowedDirs is returned when a resolved artifact escapes the configured allowlist.
	ErrArtifactOutsideAllowedDirs = errors.New("plugin artifact outside allowed directories")

	// ErrChecksumMismatch is returned when the artifact digest differs from the configured checksum.
	ErrChecksumMismatch = errors.New("plugin checksum mismatch")

	// ErrSignatureVerificationFailed is returned when a detached artifact signature cannot be verified.
	ErrSignatureVerificationFailed = errors.New("plugin signature verification failed")
)

const (
	detachedSignatureAlgorithmRaw    = "Ed"
	detachedSignatureAlgorithmHashed = "ED"
	detachedSignatureKeyIDSize       = 8
	minisignCommentPrefix            = "untrusted comment: "
	minisignTrustedCommentPrefix     = "trusted comment: "
)

// Verifier validates configured plugin artifacts before plugin.Open is allowed.
type Verifier struct {
	logger *slog.Logger
}

// VerifierOption customizes artifact verification.
type VerifierOption func(*Verifier)

// VerifiedModule describes a module whose loader-owned artifact checks completed.
type VerifiedModule struct {
	Module        config.PluginModule
	Signer        *config.PluginTrustSigner
	ArtifactPath  string
	SignaturePath string
}

type detachedPublicKey struct {
	keyID []byte
	key   ed25519.PublicKey
}

type detachedSignature struct {
	keyID           []byte
	signature       []byte
	globalSignature []byte
	algorithm       string
	trustedComment  string
}

// NewVerifier returns the default plugin artifact verifier.
func NewVerifier(options ...VerifierOption) Verifier {
	verifier := Verifier{}
	for _, option := range options {
		option(&verifier)
	}

	return verifier
}

// WithVerificationLogger configures structured artifact verification logging.
func WithVerificationLogger(logger *slog.Logger) VerifierOption {
	return func(verifier *Verifier) {
		verifier.logger = logger
	}
}

// Verify validates all configured plugin artifacts and returns canonical paths.
func (v Verifier) Verify(plugins *config.PluginsSection) ([]VerifiedModule, error) {
	if err := config.ValidatePlugins(plugins); err != nil {
		v.logVerificationConfigFailure(err)

		return nil, err
	}

	if plugins == nil || len(plugins.Modules) == 0 {
		return nil, nil
	}

	allowedDirs, err := canonicalAllowedDirs(plugins.AllowedDirs)
	if err != nil {
		return nil, err
	}

	verified := make([]VerifiedModule, 0, len(plugins.Modules))
	for index := range plugins.Modules {
		moduleConfig := &plugins.Modules[index]
		v.logVerificationStart(plugins, moduleConfig)

		module, err := v.verifyModule(plugins, allowedDirs, moduleConfig)
		if err != nil {
			v.logVerificationFailure(moduleConfig, err)

			return nil, err
		}

		v.logVerificationSuccess(plugins, module)
		verified = append(verified, module)
	}

	return verified, nil
}

// verifyModule verifies one configured module artifact.
func (v Verifier) verifyModule(
	plugins *config.PluginsSection,
	allowedDirs []string,
	module *config.PluginModule,
) (VerifiedModule, error) {
	artifactPath, err := canonicalFilePath(module.Path)
	if err != nil {
		return VerifiedModule{}, err
	}

	if !config.PluginPathWithinAllowedDirs(artifactPath, allowedDirs) {
		return VerifiedModule{}, fmt.Errorf("%w: %s", ErrArtifactOutsideAllowedDirs, artifactPath)
	}

	if err := v.verifyChecksum(plugins.EffectiveVerificationPolicy(), module, artifactPath); err != nil {
		return VerifiedModule{}, err
	}

	signaturePath, signer, err := v.verifySignature(plugins, module, artifactPath)
	if err != nil {
		return VerifiedModule{}, err
	}

	return VerifiedModule{
		Module:        *module,
		Signer:        signer,
		ArtifactPath:  artifactPath,
		SignaturePath: signaturePath,
	}, nil
}

// verifyChecksum verifies SHA-256 metadata when policy or configured fields require it.
func (v Verifier) verifyChecksum(policy string, module *config.PluginModule, artifactPath string) error {
	if policy == config.PluginVerificationPolicyOff || module.Checksum == "" {
		return nil
	}

	checksum, err := config.ParsePluginChecksum(module.Checksum)
	if err != nil {
		return err
	}

	actual, err := artifactSHA256(artifactPath)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(actual, checksum.Digest) != 1 {
		return fmt.Errorf("%w: %s", ErrChecksumMismatch, module.Name)
	}

	return nil
}

// verifySignature verifies configured minisign/signify-style detached signatures.
func (v Verifier) verifySignature(
	plugins *config.PluginsSection,
	module *config.PluginModule,
	artifactPath string,
) (string, *config.PluginTrustSigner, error) {
	if plugins.EffectiveVerificationPolicy() == config.PluginVerificationPolicyOff || module.Signature == "" {
		return "", nil, nil
	}

	signatureRef, err := config.ParsePluginSignatureRef(module.Signature)
	if err != nil {
		return "", nil, err
	}

	signaturePath, err := canonicalFilePath(signatureRef.Path)
	if err != nil {
		return "", nil, err
	}

	signer, ok := plugins.SignerByID(module.Signer)
	if !ok || signer == nil {
		return signaturePath, nil, fmt.Errorf("%w: trusted signer %q not configured", ErrSignatureVerificationFailed, module.Signer)
	}

	publicKey, err := loadDetachedPublicKey(*signer)
	if err != nil {
		return signaturePath, signer, err
	}

	if err := verifyDetachedSignature(signatureRef.Format, artifactPath, signaturePath, publicKey); err != nil {
		return signaturePath, signer, err
	}

	return signaturePath, signer, nil
}

// loadDetachedPublicKey reads the trusted signer key from inline text or file.
func loadDetachedPublicKey(signer config.PluginTrustSigner) (detachedPublicKey, error) {
	if signer.PublicKey != "" {
		return parseDetachedPublicKey([]byte(signer.PublicKey))
	}

	keyPath, err := canonicalFilePath(signer.PublicKeyFile)
	if err != nil {
		return detachedPublicKey{}, err
	}

	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return detachedPublicKey{}, fmt.Errorf("read plugin signer public key %q: %w", keyPath, err)
	}

	return parseDetachedPublicKey(raw)
}

// parseDetachedPublicKey decodes a minisign/signify public key payload.
func parseDetachedPublicKey(raw []byte) (detachedPublicKey, error) {
	blob, err := decodeDetachedPayload(raw, 2+detachedSignatureKeyIDSize+ed25519.PublicKeySize)
	if err != nil {
		return detachedPublicKey{}, fmt.Errorf("%w: invalid public key: %v", ErrSignatureVerificationFailed, err)
	}

	if string(blob[:2]) != detachedSignatureAlgorithmRaw {
		return detachedPublicKey{}, fmt.Errorf("%w: unsupported public key algorithm", ErrSignatureVerificationFailed)
	}

	return detachedPublicKey{
		keyID: append([]byte{}, blob[2:2+detachedSignatureKeyIDSize]...),
		key:   append(ed25519.PublicKey{}, blob[2+detachedSignatureKeyIDSize:]...),
	}, nil
}

// verifyDetachedSignature dispatches verification by configured signature format.
func verifyDetachedSignature(format string, artifactPath string, signaturePath string, publicKey detachedPublicKey) error {
	raw, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("read plugin signature %q: %w", signaturePath, err)
	}

	switch format {
	case config.PluginSignatureFormatMinisign:
		signature, err := parseMinisignSignature(raw)
		if err != nil {
			return err
		}

		return verifyMinisignSignature(artifactPath, publicKey, signature)
	case config.PluginSignatureFormatSignify:
		signature, err := parseSignifySignature(raw)
		if err != nil {
			return err
		}

		return verifyPrimaryDetachedSignature(artifactPath, publicKey, signature)
	default:
		return fmt.Errorf("%w: unsupported signature format %q", ErrSignatureVerificationFailed, format)
	}
}

// parseMinisignSignature decodes a minisign signature and trusted-comment signature.
func parseMinisignSignature(raw []byte) (detachedSignature, error) {
	lines := splitDetachedLines(raw)
	if len(lines) < 4 {
		return detachedSignature{}, fmt.Errorf("%w: minisign signature must contain four lines", ErrSignatureVerificationFailed)
	}

	if !strings.HasPrefix(lines[0], minisignCommentPrefix) {
		return detachedSignature{}, fmt.Errorf("%w: minisign untrusted comment missing", ErrSignatureVerificationFailed)
	}

	signature, err := parseDetachedSignatureBlob(lines[1])
	if err != nil {
		return detachedSignature{}, err
	}

	trustedComment, ok := strings.CutPrefix(lines[2], minisignTrustedCommentPrefix)
	if !ok {
		return detachedSignature{}, fmt.Errorf("%w: minisign trusted comment missing", ErrSignatureVerificationFailed)
	}

	globalSignature, err := decodeBase64Payload(lines[3], ed25519.SignatureSize)
	if err != nil {
		return detachedSignature{}, fmt.Errorf("%w: invalid minisign trusted-comment signature: %v", ErrSignatureVerificationFailed, err)
	}

	signature.globalSignature = globalSignature
	signature.trustedComment = trustedComment

	return signature, nil
}

// parseSignifySignature decodes a signify-style detached signature.
func parseSignifySignature(raw []byte) (detachedSignature, error) {
	lines := splitDetachedLines(raw)
	if len(lines) < 2 {
		return detachedSignature{}, fmt.Errorf("%w: signify signature must contain two lines", ErrSignatureVerificationFailed)
	}

	if !strings.HasPrefix(lines[0], minisignCommentPrefix) {
		return detachedSignature{}, fmt.Errorf("%w: signify untrusted comment missing", ErrSignatureVerificationFailed)
	}

	return parseDetachedSignatureBlob(lines[1])
}

// parseDetachedSignatureBlob decodes the algorithm, key ID, and Ed25519 signature.
func parseDetachedSignatureBlob(value string) (detachedSignature, error) {
	blob, err := decodeBase64Payload(value, 2+detachedSignatureKeyIDSize+ed25519.SignatureSize)
	if err != nil {
		return detachedSignature{}, fmt.Errorf("%w: invalid signature payload: %v", ErrSignatureVerificationFailed, err)
	}

	algorithm := string(blob[:2])
	if algorithm != detachedSignatureAlgorithmRaw && algorithm != detachedSignatureAlgorithmHashed {
		return detachedSignature{}, fmt.Errorf("%w: unsupported signature algorithm", ErrSignatureVerificationFailed)
	}

	return detachedSignature{
		algorithm: algorithm,
		keyID:     append([]byte{}, blob[2:2+detachedSignatureKeyIDSize]...),
		signature: append([]byte{}, blob[2+detachedSignatureKeyIDSize:]...),
	}, nil
}

// verifyMinisignSignature verifies both the artifact and trusted comment signatures.
func verifyMinisignSignature(artifactPath string, publicKey detachedPublicKey, signature detachedSignature) error {
	if err := verifyPrimaryDetachedSignature(artifactPath, publicKey, signature); err != nil {
		return err
	}

	commentMessage := append(append([]byte{}, signature.signature...), []byte(signature.trustedComment)...)
	if !ed25519.Verify(publicKey.key, commentMessage, signature.globalSignature) {
		return fmt.Errorf("%w: minisign trusted-comment signature mismatch", ErrSignatureVerificationFailed)
	}

	return nil
}

// verifyPrimaryDetachedSignature verifies the artifact payload signature.
func verifyPrimaryDetachedSignature(artifactPath string, publicKey detachedPublicKey, signature detachedSignature) error {
	if subtle.ConstantTimeCompare(publicKey.keyID, signature.keyID) != 1 {
		return fmt.Errorf("%w: signer key id mismatch", ErrSignatureVerificationFailed)
	}

	message, err := artifactSignatureMessage(artifactPath, signature.algorithm)
	if err != nil {
		return err
	}

	if !ed25519.Verify(publicKey.key, message, signature.signature) {
		return fmt.Errorf("%w: artifact signature mismatch", ErrSignatureVerificationFailed)
	}

	return nil
}

// artifactSignatureMessage returns the raw or BLAKE2b-prehashed artifact bytes.
func artifactSignatureMessage(path string, algorithm string) ([]byte, error) {
	switch algorithm {
	case detachedSignatureAlgorithmRaw:
		message, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read plugin artifact %q for signature verification: %w", path, err)
		}

		return message, nil
	case detachedSignatureAlgorithmHashed:
		sum, err := artifactBLAKE2b512(path)
		if err != nil {
			return nil, err
		}

		return sum, nil
	default:
		return nil, fmt.Errorf("%w: unsupported signature algorithm", ErrSignatureVerificationFailed)
	}
}

// artifactBLAKE2b512 streams an artifact and returns a minisign-compatible prehash.
func artifactBLAKE2b512(path string) ([]byte, error) {
	hasher, err := blake2b.New512(nil)
	if err != nil {
		return nil, fmt.Errorf("create BLAKE2b hasher: %w", err)
	}

	return artifactHash(path, hasher)
}

// decodeDetachedPayload extracts one base64 payload from key text that may include comments.
func decodeDetachedPayload(raw []byte, expectedSize int) ([]byte, error) {
	lines := splitDetachedLines(raw)
	if len(lines) == 0 {
		return nil, fmt.Errorf("payload is empty")
	}

	var lastErr error

	for _, line := range lines {
		if strings.HasPrefix(line, minisignCommentPrefix) {
			continue
		}

		payload, err := decodeBase64Payload(line, expectedSize)
		if err == nil {
			return payload, nil
		}

		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("base64 payload is missing")
}

// decodeBase64Payload decodes padded or raw standard base64 and checks its size.
func decodeBase64Payload(value string, expectedSize int) ([]byte, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return nil, fmt.Errorf("payload is empty")
	}

	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		payload, err := encoding.DecodeString(text)
		if err == nil {
			if len(payload) != expectedSize {
				return nil, fmt.Errorf("payload has %d bytes, want %d", len(payload), expectedSize)
			}

			return payload, nil
		}
	}

	return nil, fmt.Errorf("payload is not valid base64")
}

// splitDetachedLines returns non-empty comment and payload lines without line endings.
func splitDetachedLines(raw []byte) []string {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	parts := strings.Split(text, "\n")
	lines := make([]string, 0, len(parts))

	for _, part := range parts {
		line := strings.TrimRight(part, "\r")
		if line == "" {
			continue
		}

		lines = append(lines, line)
	}

	return lines
}

// canonicalAllowedDirs resolves configured allowlist directories through symlinks.
func canonicalAllowedDirs(allowedDirs []string) ([]string, error) {
	resolved := make([]string, 0, len(allowedDirs))

	for _, allowedDir := range allowedDirs {
		path, err := canonicalDirectoryPath(allowedDir)
		if err != nil {
			return nil, err
		}

		resolved = append(resolved, path)
	}

	return resolved, nil
}

// canonicalDirectoryPath returns a symlink-resolved absolute directory path.
func canonicalDirectoryPath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve plugin directory %q: %w", path, err)
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat plugin directory %q: %w", resolved, err)
	}

	if !info.IsDir() {
		return "", fmt.Errorf("plugin allowed directory %q is not a directory", resolved)
	}

	return resolved, nil
}

// canonicalFilePath returns a symlink-resolved absolute file path.
func canonicalFilePath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve plugin artifact %q: %w", path, err)
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat plugin artifact %q: %w", resolved, err)
	}

	if info.IsDir() {
		return "", fmt.Errorf("plugin artifact %q is a directory", resolved)
	}

	return resolved, nil
}

// artifactSHA256 streams an artifact and returns its SHA-256 digest.
func artifactSHA256(path string) ([]byte, error) {
	hasher := sha256.New()

	return artifactHash(path, hasher)
}

// artifactHash streams an artifact through the supplied hash.
func artifactHash(path string, hasher hash.Hash) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open plugin artifact %q: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("hash plugin artifact %q: %w", path, err)
	}

	return hasher.Sum(nil), nil
}

// logVerificationConfigFailure emits a config-level artifact verification failure.
func (v Verifier) logVerificationConfigFailure(err error) {
	if v.logger == nil {
		return
	}

	_ = level.Error(v.logger).Log(
		definitions.LogKeyMsg, "Native plugin artifact verification configuration failed",
		"plugin_error_class", "verification_config",
		definitions.LogKeyError, err,
	)
}

// logVerificationStart emits a bounded per-module verification start record.
func (v Verifier) logVerificationStart(plugins *config.PluginsSection, module *config.PluginModule) {
	if v.logger == nil || module == nil {
		return
	}

	_ = level.Debug(v.logger).Log(
		definitions.LogKeyMsg, "Native plugin artifact verification started",
		"plugin_module", module.Name,
		"plugin_path", module.Path,
		"plugin_verification_policy", plugins.EffectiveVerificationPolicy(),
		"plugin_checksum_configured", module.Checksum != "",
		"plugin_signature_configured", module.Signature != "",
		"plugin_signer", module.Signer,
	)
}

// logVerificationSuccess emits a bounded per-module verification success record.
func (v Verifier) logVerificationSuccess(plugins *config.PluginsSection, module VerifiedModule) {
	if v.logger == nil {
		return
	}

	_ = level.Debug(v.logger).Log(
		definitions.LogKeyMsg, "Native plugin artifact verification completed",
		"plugin_module", module.Module.Name,
		"plugin_path", module.ArtifactPath,
		"plugin_verification_policy", plugins.EffectiveVerificationPolicy(),
		"plugin_checksum_configured", module.Module.Checksum != "",
		"plugin_signature_configured", module.Module.Signature != "",
		"plugin_signer", module.Module.Signer,
	)
}

// logVerificationFailure emits a bounded per-module verification failure record.
func (v Verifier) logVerificationFailure(module *config.PluginModule, err error) {
	if v.logger == nil || module == nil {
		return
	}

	_ = level.Error(v.logger).Log(
		definitions.LogKeyMsg, "Native plugin artifact verification failed",
		"plugin_module", module.Name,
		"plugin_path", module.Path,
		"plugin_error_class", "verification",
		definitions.LogKeyError, err,
	)
}
