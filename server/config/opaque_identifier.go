package config

import (
	"path/filepath"
	"slices"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// OpaqueIdentifierKeySize is the required byte length of mounted HMAC-SHA-256 keys.
const OpaqueIdentifierKeySize = 32

// SecretFileReference identifies an absolute mounted secret file without embedding material.
type SecretFileReference struct {
	File string `mapstructure:"file"`
}

// OpaqueIdentifierKeyReference binds an explicit key version to host-owned secret material.
type OpaqueIdentifierKeyReference struct {
	Version   string              `mapstructure:"version"`
	SecretRef SecretFileReference `mapstructure:"secret_ref"`
}

// OpaqueIdentifierScopeConfig separates one scope's write and rotation keys.
type OpaqueIdentifierScopeConfig struct {
	Previous *OpaqueIdentifierKeyReference `mapstructure:"previous" validate:"omitempty"`
	Active   OpaqueIdentifierKeyReference  `mapstructure:"active"`
	Scope    string                        `mapstructure:"scope"`
}

// OpaqueIdentifierTaggerConfig configures a closed set of host-owned key scopes.
type OpaqueIdentifierTaggerConfig struct {
	Scopes []OpaqueIdentifierScopeConfig `mapstructure:"scopes"`
}

// ValidateOpaqueIdentifierTaggerConfig validates references without reading or displaying key material.
func ValidateOpaqueIdentifierTaggerConfig(cfg *OpaqueIdentifierTaggerConfig) error {
	if cfg == nil {
		return nil
	}

	if len(cfg.Scopes) == 0 || len(cfg.Scopes) > 32 {
		return newPluginValidationProblem("plugins.opaque_identifier_tagger.scopes", "requires 1..32 scope declarations")
	}

	seen := make(map[string]struct{}, len(cfg.Scopes))
	for _, scope := range cfg.Scopes {
		if pluginapi.ValidateOpaqueIdentifierLabel(scope.Scope, pluginapi.MaximumOpaqueIdentifierLabelLength) != nil {
			return invalidOpaqueIdentifierConfig()
		}

		if _, exists := seen[scope.Scope]; exists {
			return invalidOpaqueIdentifierConfig()
		}

		seen[scope.Scope] = struct{}{}
		if !validOpaqueIdentifierKeyReference(scope.Active) {
			return invalidOpaqueIdentifierConfig()
		}

		if scope.Previous != nil && (!validOpaqueIdentifierKeyReference(*scope.Previous) || scope.Previous.Version == scope.Active.Version || scope.Previous.SecretRef == scope.Active.SecretRef) {
			return invalidOpaqueIdentifierConfig()
		}
	}

	return nil
}

// validOpaqueIdentifierKeyReference enforces canonical versions and mounted absolute file references.
func validOpaqueIdentifierKeyReference(key OpaqueIdentifierKeyReference) bool {
	return pluginapi.ValidateOpaqueIdentifierLabel(key.Version, pluginapi.MaximumOpaqueIdentifierVersionLength) == nil &&
		filepath.IsAbs(key.SecretRef.File) && filepath.Clean(key.SecretRef.File) == key.SecretRef.File
}

// invalidOpaqueIdentifierConfig emits a stable value-free configuration diagnostic.
func invalidOpaqueIdentifierConfig() error {
	return newPluginValidationProblem("plugins.opaque_identifier_tagger", "requires unique bounded scopes and distinct versioned absolute secret references")
}

// SecretFiles returns the exact mounted inputs for candidate-owned artifact capture.
func (c *OpaqueIdentifierTaggerConfig) SecretFiles() []string {
	if c == nil {
		return nil
	}

	files := make([]string, 0, len(c.Scopes)*2)
	for _, scope := range c.Scopes {
		files = append(files, scope.Active.SecretRef.File)
		if scope.Previous != nil {
			files = append(files, scope.Previous.SecretRef.File)
		}
	}

	return files
}

// Clone detaches all mutable configuration slices and optional references.
func (c *OpaqueIdentifierTaggerConfig) Clone() *OpaqueIdentifierTaggerConfig {
	if c == nil {
		return nil
	}

	cloned := &OpaqueIdentifierTaggerConfig{Scopes: slices.Clone(c.Scopes)}
	for index := range cloned.Scopes {
		if c.Scopes[index].Previous != nil {
			previous := *c.Scopes[index].Previous
			cloned.Scopes[index].Previous = &previous
		}
	}

	return cloned
}

// validateSealedOpaqueIdentifierKeys verifies mounted key lengths before runtime startup.
func validateSealedOpaqueIdentifierKeys(cfg File, snapshot *ArtifactSnapshot) error {
	if cfg == nil || cfg.GetPlugins() == nil {
		return nil
	}

	for _, path := range cfg.GetPlugins().OpaqueIdentifierTagger.SecretFiles() {
		content, err := snapshot.ReadFile(path)
		valid := err == nil && len(content) == OpaqueIdentifierKeySize
		clear(content)

		if !valid {
			return newPluginValidationProblem("plugins.opaque_identifier_tagger", "mounted secret must contain exactly 32 key bytes")
		}
	}

	return nil
}
