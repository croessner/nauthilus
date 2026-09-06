package policyfx

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
)

// TestOpaqueIdentifierKeyChangesRequireProcessRestart rejects same-path secret replacement before commit.
func TestOpaqueIdentifierKeyChangesRequireProcessRestart(t *testing.T) {
	artifacts := newRestartBaselineArtifacts(t)
	keyPath := filepath.Join(t.TempDir(), "opaque-key")
	writeRestartBaselineArtifact(t, keyPath, strings.Repeat("a", 32))
	tagger := &config.OpaqueIdentifierTaggerConfig{Scopes: []config.OpaqueIdentifierScopeConfig{{
		Scope: "workflow", Active: config.OpaqueIdentifierKeyReference{Version: "current", SecretRef: config.SecretFileReference{File: keyPath}},
	}}}
	baseline := restartBaselineCandidate(t, artifacts)
	baseline.Plugins.OpaqueIdentifierTagger = tagger.Clone()

	validator, err := NewRestartBaseline(baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer validator.Close()

	candidate := restartBaselineCandidate(t, artifacts)
	candidate.Plugins.OpaqueIdentifierTagger = tagger.Clone()

	writeRestartBaselineArtifact(t, keyPath, strings.Repeat("b", 32))

	if err = validator.Validate(candidate); !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("key replacement error=%v", err)
	}
}
