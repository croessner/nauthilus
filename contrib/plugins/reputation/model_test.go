package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// TestASNAbsenceFingerprintPreservesUnaffectedModels prevents silently reusing old ASN attribution semantics.
func TestASNAbsenceFingerprintPreservesUnaffectedModels(t *testing.T) {
	for _, withASN := range []bool{false, true} {
		cfg := testConfig(t)
		if withASN {
			cfg = testASNObservationConfig(t)
		}

		model, err := compileModel(cfg)
		requireNoError(t, err)

		legacy := canonicalIngestionSemantics(cfg)
		legacy.ASNAbsencePolicy = ""
		encoded, err := json.Marshal(legacy)
		requireNoError(t, err)

		digest := sha256.Sum256(encoded)
		legacyFingerprint := hex.EncodeToString(digest[:])

		if (model.fingerprint != legacyFingerprint) != withASN {
			t.Fatal("ASN compatibility boundary changed an unaffected model or reused old attribution semantics")
		}
	}
}

// TestModelFingerprintBindsIngestionButNotReadTransforms requires new model identity for changed evidence semantics.
func TestModelFingerprintBindsIngestionButNotReadTransforms(t *testing.T) {
	baseline, err := compileModel(testConfig(t))
	requireNoError(t, err)

	tests := []struct {
		name      string
		mutate    func(map[string]any)
		different bool
	}{
		{"weight", func(raw map[string]any) {
			raw["signals"].(map[string]any)["scan.clean"].(map[string]any)["weight"] = 0.4
		}, true},
		{"half life", func(raw map[string]any) {
			raw["profiles"].(map[string]any)["fast"].(map[string]any)["half_life"] = "8h"
		}, true},
		{"source caps", func(raw map[string]any) {
			raw["source_class_caps"].(map[string]any)["mail_filter"].(map[string]any)["trust"] = 30.0
		}, true},
		{"network prefix", func(raw map[string]any) { raw["network_subjects"].(map[string]any)["ipv4_prefix"] = 25 }, true},
		{"subject scope", func(raw map[string]any) { raw["subject_scope"] = "other-subject" }, true},
		{"normalizer", func(raw map[string]any) { raw["account_normalization"] = "lowercase" }, true},
		{"read bands", func(raw map[string]any) { raw["bands"].(map[string]any)["trusted"].(map[string]any)["score"] = 0.7 }, false},
		{"read transform", func(raw map[string]any) { raw["score"].(map[string]any)["alpha"] = 3.0 }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := testConfigMap(t)
			tt.mutate(raw)
			cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
			requireNoError(t, err)
			changed, err := compileModel(cfg)
			requireNoError(t, err)

			if (changed.fingerprint != baseline.fingerprint) != tt.different {
				t.Fatal("model identity does not reflect ingestion semantics")
			}
		})
	}
}

// TestModelShadowUsesSeparateIdentityAndRetainsActiveSelection bounds calibration to one explicitly distinct model.
func TestModelShadowUsesSeparateIdentityAndRetainsActiveSelection(t *testing.T) {
	raw := testConfigMap(t)
	raw["shadow_model"] = map[string]any{"model_id": "shadow-test", "profiles": raw["profiles"], "source_class_caps": raw["source_class_caps"], "signal_weights": map[string]any{"scan.clean": 0.5}}
	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)
	models, err := compileModels(cfg)
	requireNoError(t, err)

	if len(models) != 2 || models[0].id != cfg.raw.ModelID || models[1].id != "shadow-test" || models[0].fingerprint == models[1].fingerprint {
		t.Fatal("shadow model changed or reused active model identity")
	}

	raw["shadow_model"].(map[string]any)["model_id"] = cfg.raw.ModelID
	_, err = decodeConfig(pluginregistry.NewConfigView(raw))
	requireError(t, err)
}
