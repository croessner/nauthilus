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

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	// PluginModuleTypeGo is the only native plugin type supported by the Go loader.
	PluginModuleTypeGo = "go"

	// PluginVerificationPolicyOff disables checksum and signature artifact verification.
	PluginVerificationPolicyOff = "off"
	// PluginVerificationPolicyWhenPresent verifies configured verification metadata.
	PluginVerificationPolicyWhenPresent = "when_present"
	// PluginVerificationPolicyChecksumRequired requires SHA-256 checksums for every module.
	PluginVerificationPolicyChecksumRequired = "checksum_required"
	// PluginVerificationPolicySignatureRequired requires trusted detached signatures for every module.
	PluginVerificationPolicySignatureRequired = "signature_required"

	// PluginVerificationPolicyDefault is the effective policy when the config omits one.
	PluginVerificationPolicyDefault = PluginVerificationPolicyWhenPresent

	// PluginSignatureFormatMinisign names minisign-style detached signatures.
	PluginSignatureFormatMinisign = "minisign"
	// PluginSignatureFormatSignify names signify-style detached signatures.
	PluginSignatureFormatSignify = "signify"
)

var (
	// ErrPluginConfigInvalid marks plugin loader configuration validation errors.
	ErrPluginConfigInvalid = errors.New("invalid plugin configuration")

	pluginSignerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
)

// PluginsSection configures native plugin artifact provenance and module instances.
type PluginsSection struct {
	Trust              PluginTrustSection `mapstructure:"trust" validate:"omitempty"`
	AllowedDirs        []string           `mapstructure:"allowed_dirs" validate:"omitempty,dive"`
	Modules            []PluginModule     `mapstructure:"modules" validate:"omitempty,dive"`
	VerificationPolicy string             `mapstructure:"verification_policy" validate:"omitempty"`
}

// PluginTrustSection contains trusted signing identities for plugin artifacts.
type PluginTrustSection struct {
	Signers []PluginTrustSigner `mapstructure:"signers" validate:"omitempty,dive"`
}

// PluginTrustSigner describes one trusted detached-signature public key.
type PluginTrustSigner struct {
	ID            string `mapstructure:"id" validate:"omitempty"`
	Format        string `mapstructure:"format" validate:"omitempty"`
	PublicKey     string `mapstructure:"public_key" validate:"omitempty"`
	PublicKeyFile string `mapstructure:"public_key_file" validate:"omitempty"`
}

// PluginModule configures one native plugin module instance.
type PluginModule struct {
	Config            map[string]any            `mapstructure:"config" validate:"omitempty" configschema:"opaque"`
	AllowCapabilities []pluginapi.Capability    `mapstructure:"allow_capabilities" validate:"omitempty,dive"`
	Hooks             []PluginHookAuthorization `mapstructure:"hooks" validate:"omitempty,dive"`
	Compatibility     PluginCompatibility       `mapstructure:"compatibility" validate:"omitempty"`
	Name              string                    `mapstructure:"name" validate:"omitempty"`
	Type              string                    `mapstructure:"type" validate:"omitempty"`
	Path              string                    `mapstructure:"path" validate:"omitempty"`
	Checksum          string                    `mapstructure:"checksum" validate:"omitempty"`
	Signature         string                    `mapstructure:"signature" validate:"omitempty"`
	Signer            string                    `mapstructure:"signer" validate:"omitempty"`
	StopTimeout       time.Duration             `mapstructure:"stop_timeout" validate:"omitempty"`
	Optional          bool                      `mapstructure:"optional"`
}

// PluginCompatibility contains restart-only, operator-owned legacy observability allowlists.
type PluginCompatibility struct {
	Metrics     []PluginCompatibilityMetric `mapstructure:"metrics" validate:"omitempty,dive"`
	TraceScopes []string                    `mapstructure:"trace_scopes" validate:"omitempty,dive"`
}

// PluginCompatibilityMetric describes one exact legacy collector contract.
type PluginCompatibilityMetric struct {
	Buckets []float64            `mapstructure:"buckets" validate:"omitempty,dive"`
	Labels  []string             `mapstructure:"labels" validate:"omitempty,dive"`
	Type    pluginapi.MetricType `mapstructure:"type" validate:"omitempty"`
	Name    string               `mapstructure:"name" validate:"omitempty"`
	Help    string               `mapstructure:"help" validate:"omitempty"`
}

// Definition returns a detached public API metric definition.
func (m PluginCompatibilityMetric) Definition() pluginapi.MetricDefinition {
	return pluginapi.MetricDefinition{
		Buckets:       slices.Clone(m.Buckets),
		Labels:        slices.Clone(m.Labels),
		Type:          m.Type,
		Name:          m.Name,
		Help:          m.Help,
		Compatibility: true,
	}
}

// PluginHookAuthorization configures exact bearer scopes for one registered hook.
type PluginHookAuthorization struct {
	RequiredScopes []string `mapstructure:"required_scopes" validate:"omitempty,dive"`
	Name           string   `mapstructure:"name" validate:"omitempty"`
}

// PluginChecksum is a parsed module artifact checksum reference.
type PluginChecksum struct {
	Algorithm string `mapstructure:"-"`
	Digest    []byte `mapstructure:"-"`
}

// PluginSignatureRef is a parsed detached signature reference.
type PluginSignatureRef struct {
	Format string `mapstructure:"-"`
	Path   string `mapstructure:"-"`
}

// EffectiveVerificationPolicy returns the configured policy or the default.
func (p *PluginsSection) EffectiveVerificationPolicy() string {
	if p == nil || p.VerificationPolicy == "" {
		return PluginVerificationPolicyDefault
	}

	return p.VerificationPolicy
}

// SignerByID returns the trusted signer configured for id.
func (p *PluginsSection) SignerByID(id string) (*PluginTrustSigner, bool) {
	if p == nil {
		return nil, false
	}

	for index := range p.Trust.Signers {
		if p.Trust.Signers[index].ID == id {
			return &p.Trust.Signers[index], true
		}
	}

	return nil, false
}

// ValidatePlugins validates native plugin loader configuration without opening artifacts.
func ValidatePlugins(plugins *PluginsSection) error {
	validator := pluginConfigValidator{plugins: plugins}

	return validator.validate()
}

// ValidatePluginSignerName checks the strict signer identifier grammar.
func ValidatePluginSignerName(name string) error {
	if !pluginSignerNamePattern.MatchString(name) {
		return fmt.Errorf("signer %q must match [a-z0-9][a-z0-9_-]{0,127}", name)
	}

	return nil
}

// ParsePluginChecksum parses a SHA-256 checksum reference.
func ParsePluginChecksum(value string) (PluginChecksum, error) {
	algorithm, digestText, ok := strings.Cut(value, ":")
	if !ok {
		return PluginChecksum{}, fmt.Errorf("checksum must use sha256:<hex>")
	}

	if algorithm != "sha256" {
		return PluginChecksum{}, fmt.Errorf("unsupported checksum algorithm %q", algorithm)
	}

	digest, err := hex.DecodeString(digestText)
	if err != nil {
		return PluginChecksum{}, fmt.Errorf("checksum digest must be hex: %w", err)
	}

	if len(digest) != sha256.Size {
		return PluginChecksum{}, fmt.Errorf("checksum digest must be %d bytes", sha256.Size)
	}

	return PluginChecksum{Algorithm: algorithm, Digest: digest}, nil
}

// ParsePluginSignatureRef parses a detached signature reference.
func ParsePluginSignatureRef(value string) (PluginSignatureRef, error) {
	format, path, ok := strings.Cut(value, ":")
	if !ok {
		return PluginSignatureRef{}, fmt.Errorf("signature must use <format>:<absolute path>")
	}

	if !isSupportedPluginSignatureFormat(format) {
		return PluginSignatureRef{}, fmt.Errorf("unsupported signature format %q", format)
	}

	if !filepath.IsAbs(path) {
		return PluginSignatureRef{}, fmt.Errorf("signature path must be absolute")
	}

	return PluginSignatureRef{Format: format, Path: filepath.Clean(path)}, nil
}

// PluginPathWithinAllowedDirs reports whether path is under one configured directory.
func PluginPathWithinAllowedDirs(path string, allowedDirs []string) bool {
	cleanPath := filepath.Clean(path)

	for _, allowedDir := range allowedDirs {
		if pathWithinDirectory(cleanPath, filepath.Clean(allowedDir)) {
			return true
		}
	}

	return false
}

type pluginConfigValidator struct {
	plugins *PluginsSection              `mapstructure:"-"`
	signers map[string]PluginTrustSigner `mapstructure:"-"`
}

// validate runs the full plugin configuration validation sequence.
func (v *pluginConfigValidator) validate() error {
	if v.plugins == nil {
		return nil
	}

	v.applyDefaults()

	if err := v.validatePolicy(); err != nil {
		return err
	}

	if err := v.validateAllowedDirs(); err != nil {
		return err
	}

	if err := v.validateSigners(); err != nil {
		return err
	}

	return v.validateModules()
}

// applyDefaults sets explicit values for omitted plugin config defaults.
func (v *pluginConfigValidator) applyDefaults() {
	if v.plugins.VerificationPolicy == "" {
		v.plugins.VerificationPolicy = PluginVerificationPolicyDefault
	}

	for index := range v.plugins.Modules {
		if v.plugins.Modules[index].Type == "" {
			v.plugins.Modules[index].Type = PluginModuleTypeGo
		}
	}
}

// validatePolicy checks that the verification policy is supported.
func (v *pluginConfigValidator) validatePolicy() error {
	switch v.plugins.VerificationPolicy {
	case PluginVerificationPolicyOff,
		PluginVerificationPolicyWhenPresent,
		PluginVerificationPolicyChecksumRequired,
		PluginVerificationPolicySignatureRequired:
		return nil
	default:
		return newPluginValidationProblem("plugins.verification_policy", "is not supported")
	}
}

// validateAllowedDirs checks absolute directory allowlist syntax.
func (v *pluginConfigValidator) validateAllowedDirs() error {
	if len(v.plugins.Modules) > 0 && len(v.plugins.AllowedDirs) == 0 {
		return newPluginValidationProblem("plugins.allowed_dirs", "must contain at least one directory when modules are configured")
	}

	for index, allowedDir := range v.plugins.AllowedDirs {
		if !filepath.IsAbs(allowedDir) {
			return newPluginValidationProblem(fmt.Sprintf("plugins.allowed_dirs[%d]", index), "must be an absolute path")
		}
	}

	return nil
}

// validateSigners checks trusted signer names, formats, and key sources.
func (v *pluginConfigValidator) validateSigners() error {
	v.signers = make(map[string]PluginTrustSigner, len(v.plugins.Trust.Signers))

	for index, signer := range v.plugins.Trust.Signers {
		path := fmt.Sprintf("plugins.trust.signers[%d]", index)

		if err := ValidatePluginSignerName(signer.ID); err != nil {
			return newPluginValidationProblem(path+".id", err.Error())
		}

		if !isSupportedPluginSignatureFormat(signer.Format) {
			return newPluginValidationProblem(path+".format", "is not supported")
		}

		if err := validatePluginSignerKeySource(path, signer); err != nil {
			return err
		}

		if _, exists := v.signers[signer.ID]; exists {
			return newPluginValidationProblem(path+".id", "duplicates another signer")
		}

		v.signers[signer.ID] = signer
	}

	return nil
}

// validateModules checks each configured module instance.
func (v *pluginConfigValidator) validateModules() error {
	seen := make(map[string]struct{}, len(v.plugins.Modules))
	metricOwners := make(map[string]struct{})

	for index := range v.plugins.Modules {
		if err := v.validateModule(index, &v.plugins.Modules[index], seen, metricOwners); err != nil {
			return err
		}
	}

	return nil
}

// validateModule checks one plugin module instance.
func (v *pluginConfigValidator) validateModule(
	index int,
	module *PluginModule,
	seen map[string]struct{},
	metricOwners map[string]struct{},
) error {
	path := fmt.Sprintf("plugins.modules[%d]", index)

	if err := pluginapi.ValidateModuleName(module.Name); err != nil {
		return newPluginValidationProblem(path+".name", err.Error())
	}

	if _, exists := seen[module.Name]; exists {
		return newPluginValidationProblem(path+".name", "duplicates another module")
	}

	seen[module.Name] = struct{}{}

	if err := v.validateModuleType(path, module); err != nil {
		return err
	}

	if err := v.validateModulePath(path, module); err != nil {
		return err
	}

	if err := v.validateModuleChecksum(path, module); err != nil {
		return err
	}

	if err := v.validateModuleSignature(path, module); err != nil {
		return err
	}

	if err := validatePluginCapabilities(path, module.AllowCapabilities); err != nil {
		return err
	}

	if err := validatePluginHookAuthorizations(path, module.Hooks); err != nil {
		return err
	}

	if err := validatePluginCompatibility(path, module, v.plugins.EffectiveVerificationPolicy(), metricOwners); err != nil {
		return err
	}

	return validatePluginStopTimeout(path, module.StopTimeout)
}

// validatePluginCompatibility checks signed exact observability allowlists and normalizes scopes.
func validatePluginCompatibility(
	path string,
	module *PluginModule,
	verificationPolicy string,
	metricOwners map[string]struct{},
) error {
	compatibility := &module.Compatibility
	if len(compatibility.Metrics) == 0 && len(compatibility.TraceScopes) == 0 {
		return nil
	}

	if verificationPolicy == PluginVerificationPolicyOff {
		return newPluginValidationProblem(path+".compatibility", "requires plugin signature verification")
	}

	if module.Signature == "" || module.Signer == "" {
		return newPluginValidationProblem(path+".compatibility", "requires a configured signature and trusted signer")
	}

	for index, metric := range compatibility.Metrics {
		metricPath := fmt.Sprintf("%s.compatibility.metrics[%d]", path, index)
		if err := pluginapi.ValidateCompatibilityMetric(metric.Definition()); err != nil {
			return newPluginValidationProblem(metricPath, err.Error())
		}

		if _, exists := metricOwners[metric.Name]; exists {
			return newPluginValidationProblem(metricPath+".name", "duplicates another exact compatibility metric")
		}

		metricOwners[metric.Name] = struct{}{}
	}

	normalized := make([]string, 0, len(compatibility.TraceScopes))

	seenScopes := make(map[string]struct{}, len(compatibility.TraceScopes))

	for index, scope := range compatibility.TraceScopes {
		scope = strings.TrimSpace(scope)
		if err := pluginapi.ValidateCompatibilityTraceScope(scope); err != nil {
			return newPluginValidationProblem(fmt.Sprintf("%s.compatibility.trace_scopes[%d]", path, index), err.Error())
		}

		if _, exists := seenScopes[scope]; exists {
			continue
		}

		seenScopes[scope] = struct{}{}
		normalized = append(normalized, scope)
	}

	compatibility.TraceScopes = normalized

	return nil
}

// validateModuleType checks the configured module type.
func (v *pluginConfigValidator) validateModuleType(path string, module *PluginModule) error {
	if module.Type != PluginModuleTypeGo {
		return newPluginValidationProblem(path+".type", "is not supported")
	}

	return nil
}

// validateModulePath checks absolute path syntax and directory allowlist containment.
func (v *pluginConfigValidator) validateModulePath(path string, module *PluginModule) error {
	if module.Path == "" {
		return newPluginValidationProblem(path+".path", "must not be empty")
	}

	if !filepath.IsAbs(module.Path) {
		return newPluginValidationProblem(path+".path", "must be an absolute path")
	}

	if filepath.Ext(module.Path) != ".so" {
		return newPluginValidationProblem(path+".path", "must point to a .so artifact")
	}

	if !PluginPathWithinAllowedDirs(module.Path, v.plugins.AllowedDirs) {
		return newPluginValidationProblem(path+".path", "must be inside plugins.allowed_dirs")
	}

	return nil
}

// validateModuleChecksum checks checksum syntax and policy requirements.
func (v *pluginConfigValidator) validateModuleChecksum(path string, module *PluginModule) error {
	if module.Checksum == "" {
		if v.plugins.VerificationPolicy == PluginVerificationPolicyChecksumRequired {
			return newPluginValidationProblem(path+".checksum", "is required by plugins.verification_policy")
		}

		return nil
	}

	if _, err := ParsePluginChecksum(module.Checksum); err != nil {
		return newPluginValidationProblem(path+".checksum", err.Error())
	}

	return nil
}

// validateModuleSignature checks detached signature syntax and signer references.
func (v *pluginConfigValidator) validateModuleSignature(path string, module *PluginModule) error {
	if module.Signature == "" {
		if v.plugins.VerificationPolicy == PluginVerificationPolicySignatureRequired {
			return newPluginValidationProblem(path+".signature", "is required by plugins.verification_policy")
		}

		if module.Signer != "" {
			return newPluginValidationProblem(path+".signer", "requires a signature")
		}

		return nil
	}

	signatureRef, err := ParsePluginSignatureRef(module.Signature)
	if err != nil {
		return newPluginValidationProblem(path+".signature", err.Error())
	}

	if module.Signer == "" {
		return newPluginValidationProblem(path+".signer", "is required when signature is configured")
	}

	signer, ok := v.signers[module.Signer]
	if !ok {
		return newPluginValidationProblem(path+".signer", "does not reference a trusted signer")
	}

	if signer.Format != signatureRef.Format {
		return newPluginValidationProblem(path+".signer", "format does not match signature")
	}

	return nil
}

// validatePluginSignerKeySource checks that a signer has exactly one public key source.
func validatePluginSignerKeySource(path string, signer PluginTrustSigner) error {
	hasInlineKey := signer.PublicKey != ""
	hasKeyFile := signer.PublicKeyFile != ""

	switch {
	case hasInlineKey && hasKeyFile:
		return newPluginValidationProblem(path, "must not set both public_key and public_key_file")
	case !hasInlineKey && !hasKeyFile:
		return newPluginValidationProblem(path, "must set public_key or public_key_file")
	case hasKeyFile && !filepath.IsAbs(signer.PublicKeyFile):
		return newPluginValidationProblem(path+".public_key_file", "must be an absolute path")
	default:
		return nil
	}
}

// validatePluginCapabilities checks the capability allowlist for duplicates and unsupported values.
func validatePluginCapabilities(path string, capabilities []pluginapi.Capability) error {
	seen := make(map[pluginapi.Capability]struct{}, len(capabilities))

	for index, capability := range capabilities {
		switch capability {
		case pluginapi.CapabilityCredentials, pluginapi.CapabilityMail:
		default:
			return newPluginValidationProblem(fmt.Sprintf("%s.allow_capabilities[%d]", path, index), "is not supported")
		}

		if _, exists := seen[capability]; exists {
			return newPluginValidationProblem(fmt.Sprintf("%s.allow_capabilities[%d]", path, index), "duplicates another capability")
		}

		seen[capability] = struct{}{}
	}

	return nil
}

// validatePluginHookAuthorizations normalizes exact hook scopes and rejects ambiguous entries.
func validatePluginHookAuthorizations(path string, authorizations []PluginHookAuthorization) error {
	seen := make(map[string]struct{}, len(authorizations))

	for index := range authorizations {
		authorization := &authorizations[index]
		authorizationPath := fmt.Sprintf("%s.hooks[%d]", path, index)

		if err := pluginapi.ValidateComponentName(authorization.Name); err != nil {
			return newPluginValidationProblem(authorizationPath+".name", err.Error())
		}

		if _, exists := seen[authorization.Name]; exists {
			return newPluginValidationProblem(authorizationPath+".name", "duplicates another hook authorization")
		}

		normalized, err := pluginapi.NormalizeHookRequiredScopes(authorization.RequiredScopes)
		if err != nil {
			return newPluginValidationProblem(authorizationPath+".required_scopes", err.Error())
		}

		seen[authorization.Name] = struct{}{}
		authorization.RequiredScopes = normalized
	}

	return nil
}

// validatePluginStopTimeout checks the optional module shutdown timeout.
func validatePluginStopTimeout(path string, timeout time.Duration) error {
	if timeout < 0 {
		return newPluginValidationProblem(path+".stop_timeout", "must not be negative")
	}

	return nil
}

// isSupportedPluginSignatureFormat reports whether the signature format is modeled.
func isSupportedPluginSignatureFormat(format string) bool {
	return slices.Contains([]string{PluginSignatureFormatMinisign, PluginSignatureFormatSignify}, format)
}

// pathWithinDirectory checks containment for already-clean paths.
func pathWithinDirectory(path string, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	if err != nil || relative == "." || relative == ".." {
		return false
	}

	return !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// newPluginValidationProblem wraps a canonical config problem with a typed plugin error.
func newPluginValidationProblem(path string, message string) error {
	return fmt.Errorf("%w: %w", ErrPluginConfigInvalid, NewValidationProblem(path, message))
}
