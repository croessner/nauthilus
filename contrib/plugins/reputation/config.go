// Package main implements configuration-owned reputation evidence admission.
package main

import (
	"errors"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

var errConfiguration = errors.New("invalid reputation configuration")
var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

const (
	stateSchema             = "reputation-state.v1"
	maximumRetention        = 365 * 24 * time.Hour
	maximumSubjects         = 8
	maximumExpandedSubjects = 24
	bindingAPI              = "api_caller"
	bindingHost             = "host_execution"
	originExternal          = "external_pre_policy"
	originBackend           = "host_backend_outcome"
	originAuthoritative     = "authoritative_external"
)

type rawConfig struct {
	IPOverrideNetworks              []string                 `mapstructure:"ip_override_networks"`
	AuthLearning                    *authLearningConfig      `mapstructure:"auth_learning"`
	Bands                           bandConfig               `mapstructure:"bands"`
	ShadowModel                     *shadowModelConfig       `mapstructure:"shadow_model"`
	AllocationDrainGeneration       int                      `mapstructure:"allocation_drain_generation"`
	MaximumEventManifestsPerSource  int                      `mapstructure:"maximum_event_manifests_per_source"`
	MaximumSeenEventsPerSubject     int                      `mapstructure:"maximum_seen_events_per_subject"`
	TargetBindings                  []targetBindingConfig    `mapstructure:"target_bindings"`
	Sources                         map[string]sourceConfig  `mapstructure:"sources"`
	Signals                         map[string]signalConfig  `mapstructure:"signals"`
	Profiles                        map[string]profileConfig `mapstructure:"profiles"`
	SourceClassCaps                 map[string]sourceCap     `mapstructure:"source_class_caps"`
	Services                        []string                 `mapstructure:"services"`
	StateSchema                     string                   `mapstructure:"state_schema"`
	ModelID                         string                   `mapstructure:"model_id"`
	SubjectScope                    string                   `mapstructure:"subject_scope"`
	ManifestScope                   string                   `mapstructure:"manifest_scope"`
	AccountNormalization            string                   `mapstructure:"account_normalization"`
	Retention                       string                   `mapstructure:"retention"`
	EventManifestTTL                string                   `mapstructure:"event_manifest_ttl"`
	SubjectSeenTTL                  string                   `mapstructure:"subject_seen_ttl"`
	MaximumRetryHorizon             string                   `mapstructure:"maximum_retry_horizon"`
	NetworkSubjects                 networkConfig            `mapstructure:"network_subjects"`
	Score                           scoreConfig              `mapstructure:"score"`
	MaximumSourceClasses            int                      `mapstructure:"maximum_source_classes"`
	MaximumNewSubjectsPerSourceHour int                      `mapstructure:"maximum_new_subjects_per_source_hour"`
}

type networkConfig struct {
	IPv4Prefix int `mapstructure:"ipv4_prefix"`
	IPv6Prefix int `mapstructure:"ipv6_prefix"`
}

type scoreConfig struct {
	Alpha       float64 `mapstructure:"alpha"`
	Saturation  float64 `mapstructure:"saturation"`
	Temperature float64 `mapstructure:"temperature"`
}

type sourceCap struct {
	Risk    float64 `mapstructure:"risk"`
	Trust   float64 `mapstructure:"trust"`
	Samples float64 `mapstructure:"samples"`
}

type profileConfig struct {
	HalfLife string `mapstructure:"half_life"`
}

type configuration struct {
	overrideNetworks []netip.Prefix
	asnFacts         map[string]string
	shadow           *configuration
	bindings         map[pluginapi.DecisionTargetSelector]targetBindingConfig
	raw              rawConfig
	apiSources       map[string]*sourcePolicy
	internalSources  map[executionKey]*sourcePolicy
	signals          map[string]*signalPolicy
	profiles         map[string]time.Duration
	retention        time.Duration
	manifestTTL      time.Duration
	seenTTL          time.Duration
	retryHorizon     time.Duration
}

// decodeConfig compiles the strict, explicit operator-owned catalog before registration.
func decodeConfig(view pluginapi.ConfigView) (*configuration, error) {
	var raw rawConfig

	if view == nil || view.IsZero() {
		return nil, errConfiguration
	}

	if err := view.Decode(&raw); err != nil {
		return nil, errConfiguration
	}

	return compileConfiguration(raw)
}

// compileConfiguration centralizes validation for both active and explicitly derived shadow snapshots.
func compileConfiguration(raw rawConfig) (*configuration, error) {
	cfg := &configuration{raw: raw}
	if err := cfg.validateModel(); err != nil {
		return nil, err
	}

	if err := cfg.compileSignals(); err != nil {
		return nil, err
	}

	if err := cfg.compileSources(); err != nil {
		return nil, err
	}

	if err := cfg.validateAuthLearning(); err != nil {
		return nil, err
	}

	if err := cfg.compileExtractors(); err != nil {
		return nil, err
	}

	if err := cfg.validateBands(); err != nil {
		return nil, err
	}

	if err := cfg.compileOverrideNetworks(); err != nil {
		return nil, err
	}

	if err := cfg.compileShadow(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validateModel requires bounded storage, tagging, score and normalization choices without implicit defaults.
func (c *configuration) validateModel() error {
	r := c.raw
	if r.StateSchema != stateSchema || !identifierPattern.MatchString(r.ModelID) ||
		pluginapi.ValidateOpaqueIdentifierLabel(r.SubjectScope, pluginapi.MaximumOpaqueIdentifierLabelLength) != nil ||
		pluginapi.ValidateOpaqueIdentifierLabel(r.ManifestScope, pluginapi.MaximumOpaqueIdentifierLabelLength) != nil || r.SubjectScope == r.ManifestScope {
		return errConfiguration
	}

	if err := validateNormalizationAndScore(r); err != nil {
		return err
	}

	if !validStateCardinality(r) {
		return errConfiguration
	}

	if err := c.validateRetention(); err != nil {
		return err
	}

	return c.compileProfilesAndCaps()
}

// validateRetention rejects incomplete or impossible idempotency retention windows.
func (c *configuration) validateRetention() error {
	bindings := []struct {
		text   string
		target *time.Duration
	}{
		{c.raw.Retention, &c.retention}, {c.raw.EventManifestTTL, &c.manifestTTL},
		{c.raw.SubjectSeenTTL, &c.seenTTL}, {c.raw.MaximumRetryHorizon, &c.retryHorizon},
	}
	for _, binding := range bindings {
		value, err := durationBound(binding.text, maximumRetention, false)
		if err != nil {
			return err
		}

		*binding.target = value
	}

	if c.manifestTTL > c.retention || c.seenTTL > c.retention || c.retryHorizon > c.manifestTTL || c.seenTTL < c.manifestTTL {
		return errConfiguration
	}

	return nil
}

// compileProfilesAndCaps fixes the bounded accumulator vocabulary used by later state owners.
func (c *configuration) compileProfilesAndCaps() error {
	r := c.raw
	if len(r.Profiles) != 3 || r.MaximumSourceClasses < 1 || r.MaximumSourceClasses > 8 ||
		len(r.SourceClassCaps) < 1 || len(r.SourceClassCaps) > r.MaximumSourceClasses ||
		r.MaximumNewSubjectsPerSourceHour < 1 || r.MaximumNewSubjectsPerSourceHour > 100000 {
		return errConfiguration
	}

	c.profiles = make(map[string]time.Duration, 3)
	for _, name := range []string{profileFast, profileOperational, profileBaseline} {
		value, err := durationBound(r.Profiles[name].HalfLife, c.retention, false)
		if err != nil {
			return err
		}

		c.profiles[name] = value
	}

	if c.profiles[profileFast] > c.profiles[profileOperational] || c.profiles[profileOperational] > c.profiles[profileBaseline] {
		return errConfiguration
	}

	return validateClassCaps(r.SourceClassCaps)
}

// durationBound parses explicit finite durations with caller-selected zero semantics.
func durationBound(text string, maximum time.Duration, zero bool) (time.Duration, error) {
	value, err := time.ParseDuration(text)
	if err != nil || value < 0 || (!zero && value == 0) || value > maximum {
		return 0, errConfiguration
	}

	return value, nil
}

// nonnegativeBound rejects NaN, infinities and measurements outside a finite interval.
func nonnegativeBound(value, maximum float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= maximum
}

// positiveBound checks a finite strictly positive configuration value.
func positiveBound(value, maximum float64) bool { return value > 0 && nonnegativeBound(value, maximum) }

// uniqueIdentifiers validates one closed bounded set without case folding or duplicate aliases.
func uniqueIdentifiers(values []string, maximum int, empty bool) bool {
	if len(values) > maximum || (!empty && len(values) == 0) {
		return false
	}

	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !identifierPattern.MatchString(value) {
			return false
		}

		if _, exists := seen[value]; exists {
			return false
		}

		seen[value] = struct{}{}
	}

	return true
}

// subjectKind identifies the only supported typed identity spaces.
func subjectKind(kind string) bool {
	return slices.Contains([]string{kindIP, kindNetwork, kindASN, kindDomain, kindAccount, kindService}, kind)
}

// validateNormalizationAndScore confines subject normalization and read transforms to explicit bounded choices.
func validateNormalizationAndScore(r rawConfig) error {
	if r.AccountNormalization != normalizeExact && r.AccountNormalization != normalizeLowercase {
		return errConfiguration
	}

	if !uniqueIdentifiers(r.Services, 64, true) || r.NetworkSubjects.IPv4Prefix < 1 || r.NetworkSubjects.IPv4Prefix > 32 ||
		r.NetworkSubjects.IPv6Prefix < 1 || r.NetworkSubjects.IPv6Prefix > 128 {
		return errConfiguration
	}

	if !positiveBound(r.Score.Alpha, 1000) || !positiveBound(r.Score.Saturation, 1000000) || !positiveBound(r.Score.Temperature, 100) {
		return errConfiguration
	}

	return nil
}

// validateClassCaps bounds each configured source-class accumulator independently.
func validateClassCaps(caps map[string]sourceCap) error {
	for class, cap := range caps {
		if !identifierPattern.MatchString(class) || !nonnegativeBound(cap.Risk, 1000000) || !nonnegativeBound(cap.Trust, 1000000) ||
			cap.Risk+cap.Trust == 0 || !positiveBound(cap.Samples, 1000000) {
			return errConfiguration
		}
	}

	return nil
}

// validStateCardinality requires explicit finite event-history ceilings in addition to transport limits.
func validStateCardinality(raw rawConfig) bool {
	return raw.AllocationDrainGeneration >= 0 && raw.AllocationDrainGeneration <= 1000000 && raw.MaximumEventManifestsPerSource >= manifestShardCount && raw.MaximumEventManifestsPerSource <= 100000 &&
		raw.MaximumSeenEventsPerSubject >= 1 && raw.MaximumSeenEventsPerSubject <= 100000
}
