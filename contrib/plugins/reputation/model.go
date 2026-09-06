package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"time"
)

type profileDefinition struct {
	Name     string  `json:"name"`
	HalfLife float64 `json:"half_life"`
}

type classDefinition struct {
	Name    string  `json:"name"`
	Risk    float64 `json:"risk"`
	Trust   float64 `json:"trust"`
	Samples float64 `json:"samples"`
}

type modelDefinition struct {
	config      *configuration
	profiles    []profileDefinition
	classes     []classDefinition
	id          string
	fingerprint string
}

type ingestionSemantics struct {
	SubjectScope         string                  `json:"subject_scope"`
	MaximumManifests     int                     `json:"maximum_manifests"`
	MaximumSeen          int                     `json:"maximum_seen"`
	Sources              map[string]sourceConfig `json:"sources"`
	Signals              map[string]signalConfig `json:"signals"`
	Profiles             []profileDefinition     `json:"profiles"`
	Classes              []classDefinition       `json:"classes"`
	Services             []string                `json:"services"`
	Schema               string                  `json:"schema"`
	AccountNormalization string                  `json:"account_normalization"`
	Network              networkConfig           `json:"network"`
	Retention            time.Duration           `json:"retention"`
	ManifestTTL          time.Duration           `json:"manifest_ttl"`
	SeenTTL              time.Duration           `json:"seen_ttl"`
	RetryHorizon         time.Duration           `json:"retry_horizon"`
	NewSubjectsPerHour   int                     `json:"new_subjects_per_hour"`
}

// compileModel hashes canonical ingestion semantics while excluding mutable read-only score transforms.
func compileModel(cfg *configuration) (*modelDefinition, error) {
	semantics := canonicalIngestionSemantics(cfg)

	encoded, err := json.Marshal(semantics)
	if err != nil {
		return nil, errConfiguration
	}

	digest := sha256.Sum256(encoded)

	return &modelDefinition{config: cfg, id: cfg.raw.ModelID, fingerprint: hex.EncodeToString(digest[:]), profiles: semantics.Profiles, classes: semantics.Classes}, nil
}

// canonicalIngestionSemantics detaches and orders all accumulator, attribution and admission dimensions.
func canonicalIngestionSemantics(cfg *configuration) ingestionSemantics {
	value := ingestionSemantics{SubjectScope: cfg.raw.SubjectScope, MaximumManifests: cfg.raw.MaximumEventManifestsPerSource, MaximumSeen: cfg.raw.MaximumSeenEventsPerSubject, Schema: cfg.raw.StateSchema, AccountNormalization: cfg.raw.AccountNormalization, Network: cfg.raw.NetworkSubjects,
		Retention: cfg.retention, ManifestTTL: cfg.manifestTTL, SeenTTL: cfg.seenTTL, RetryHorizon: cfg.retryHorizon, NewSubjectsPerHour: cfg.raw.MaximumNewSubjectsPerSourceHour,
		Services: slices.Clone(cfg.raw.Services), Sources: make(map[string]sourceConfig), Signals: make(map[string]signalConfig)}
	sort.Strings(value.Services)

	for name, halfLife := range cfg.profiles {
		value.Profiles = append(value.Profiles, profileDefinition{Name: name, HalfLife: halfLife.Seconds()})
	}

	for name, cap := range cfg.raw.SourceClassCaps {
		value.Classes = append(value.Classes, classDefinition{Name: name, Risk: cap.Risk, Trust: cap.Trust, Samples: cap.Samples})
	}

	sort.Slice(value.Profiles, func(i, j int) bool { return value.Profiles[i].Name < value.Profiles[j].Name })
	sort.Slice(value.Classes, func(i, j int) bool { return value.Classes[i].Name < value.Classes[j].Name })

	for _, source := range cfg.apiSources {
		value.Sources[source.config.SourcePolicyID] = canonicalSourceConfig(source)
	}

	for _, source := range cfg.internalSources {
		value.Sources[source.config.SourcePolicyID] = canonicalSourceConfig(source)
	}

	for name, signal := range cfg.signals {
		raw := signal.config
		raw.SourceClasses = sortedStrings(raw.SourceClasses)
		raw.Profiles = sortedStrings(raw.Profiles)
		raw.MaxEventAge = signal.maxAge.String()
		value.Signals[name] = raw
	}

	return value
}

// canonicalSourceConfig normalizes temporal aliases and set ordering without changing exact source identity.
func canonicalSourceConfig(source *sourcePolicy) sourceConfig {
	raw := source.config
	raw.AllowedSignals = sortedStrings(raw.AllowedSignals)
	raw.Binding.Targets = sortedStrings(raw.Binding.Targets)
	raw.AllowedSubjects = sortedRoleKinds(raw.AllowedSubjects)
	raw.DerivedSubjects = sortedRoleKinds(raw.DerivedSubjects)
	raw.MaximumLateness = source.lateness.String()
	raw.FutureClockSkew = source.futureSkew.String()

	return raw
}

// sortedRoleKinds detaches exact role allowlists into deterministic set order.
func sortedRoleKinds(roles map[string][]string) map[string][]string {
	result := make(map[string][]string, len(roles))
	for role, kinds := range roles {
		result[role] = sortedStrings(kinds)
	}

	return result
}

// sortedStrings returns an owned sorted representation of a validated unique set.
func sortedStrings(values []string) []string {
	result := slices.Clone(values)
	sort.Strings(result)

	return result
}
