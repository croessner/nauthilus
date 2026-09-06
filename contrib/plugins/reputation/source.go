package main

import (
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type sourceBinding struct {
	Targets         []string `mapstructure:"targets"`
	Kind            string   `mapstructure:"kind"`
	CallerPrincipal string   `mapstructure:"caller_principal"`
	Module          string   `mapstructure:"module"`
	Component       string   `mapstructure:"component"`
	ExtensionPoint  string   `mapstructure:"extension_point"`
	Operation       string   `mapstructure:"operation"`
}

type sourceConfig struct {
	AllowedSubjects   map[string][]string `mapstructure:"allowed_subjects"`
	DerivedSubjects   map[string][]string `mapstructure:"derived_subjects"`
	AllowedSignals    []string            `mapstructure:"allowed_signals"`
	Binding           sourceBinding       `mapstructure:"binding"`
	SourcePolicyID    string              `mapstructure:"source_policy_id"`
	SourceClass       string              `mapstructure:"source_class"`
	MaximumLateness   string              `mapstructure:"maximum_lateness"`
	FutureClockSkew   string              `mapstructure:"future_clock_skew"`
	ASNProvider       string              `mapstructure:"asn_provider"`
	ASNFact           string              `mapstructure:"asn_fact"`
	ASNMaxAge         string              `mapstructure:"asn_max_age"`
	MaximumSubjects   int                 `mapstructure:"maximum_subjects"`
	RequestsPerSecond int                 `mapstructure:"requests_per_second"`
	MaxConcurrency    int                 `mapstructure:"max_concurrency"`
	AllowMagnitude    bool                `mapstructure:"allow_magnitude"`
}

type sourcePolicy struct {
	asnMaxAge  time.Duration
	config     sourceConfig
	lateness   time.Duration
	futureSkew time.Duration
}

type executionKey struct {
	module    string
	component string
	extension string
	operation string
	target    pluginapi.DecisionTargetSelector
}

// identityKey copies only the host-created immutable registration identity, never caller facts.
func identityKey(identity pluginapi.ExecutionIdentityView) executionKey {
	return executionKey{identity.Module(), identity.Component(), identity.ExtensionPoint(), identity.Operation(), identity.Target()}
}

// compileSources creates disjoint exact indexes and globally unique stable source identities.
func (c *configuration) compileSources() error {
	if len(c.raw.Sources) < 1 || len(c.raw.Sources) > 64 {
		return errConfiguration
	}

	c.apiSources = make(map[string]*sourcePolicy)
	c.asnFacts = make(map[string]string)
	c.internalSources = make(map[executionKey]*sourcePolicy)
	ids := make(map[string]struct{})

	for name, raw := range c.raw.Sources {
		if !identifierPattern.MatchString(name) || !identifierPattern.MatchString(raw.SourcePolicyID) {
			return errConfiguration
		}

		if _, exists := ids[raw.SourcePolicyID]; exists {
			return errConfiguration
		}

		ids[raw.SourcePolicyID] = struct{}{}

		source, err := c.compileSource(raw)
		if err != nil {
			return err
		}

		if err := c.indexSource(source); err != nil {
			return err
		}

		if source.config.ASNFact != "" {
			previous, exists := c.asnFacts[source.config.ASNFact]
			if exists && previous != source.config.ASNProvider {
				return errConfiguration
			}

			c.asnFacts[source.config.ASNFact] = source.config.ASNProvider
		}
	}

	return nil
}

// compileSource binds temporal, fan-out and explicit rate limits to closed signal semantics.
func (c *configuration) compileSource(raw sourceConfig) (*sourcePolicy, error) {
	if _, exists := c.raw.SourceClassCaps[raw.SourceClass]; !exists {
		return nil, errConfiguration
	}

	if !validSourceLimits(raw) {
		return nil, errConfiguration
	}

	late, err := durationBound(raw.MaximumLateness, c.retention, false)
	if err != nil {
		return nil, err
	}

	skew, err := durationBound(raw.FutureClockSkew, time.Hour, true)
	if err != nil {
		return nil, err
	}

	if late+skew+c.retryHorizon > c.manifestTTL || late+skew+c.retryHorizon > c.seenTTL {
		return nil, errConfiguration
	}

	if err := c.validateSourceSignals(raw); err != nil {
		return nil, err
	}

	if err := validateSourceSubjects(raw); err != nil {
		return nil, err
	}

	var asnMaxAge time.Duration
	if raw.ASNProvider != "" {
		asnMaxAge, err = durationBound(raw.ASNMaxAge, 365*24*time.Hour, false)
		if err != nil {
			return nil, err
		}
	}

	return &sourcePolicy{config: raw, lateness: late, futureSkew: skew, asnMaxAge: asnMaxAge}, nil
}

// validateSourceSignals rejects undeclared signals and cross-origin or cross-class bindings.
func (c *configuration) validateSourceSignals(raw sourceConfig) error {
	if !uniqueIdentifiers(raw.AllowedSignals, 64, false) {
		return errConfiguration
	}

	for _, name := range raw.AllowedSignals {
		signal, exists := c.signals[name]
		if !exists || !slices.Contains(signal.config.SourceClasses, raw.SourceClass) {
			return errConfiguration
		}

		if !compatibleOrigin(raw.Binding.Kind, signal.config.EvidenceOrigin) {
			return errConfiguration
		}

		if signal.config.Magnitude == magnitudeRequired && !raw.AllowMagnitude {
			return errConfiguration
		}

		if directKind(raw.AllowedSubjects, kindASN) && signal.config.EvidenceOrigin != originAuthoritative {
			return errConfiguration
		}
	}

	return nil
}

// compatibleOrigin confines evidence origin to the authenticated or internal execution path.
func compatibleOrigin(binding, origin string) bool {
	return (binding == bindingHost && origin == originBackend) ||
		(binding == bindingAPI && (origin == originExternal || origin == originAuthoritative))
}

// validateSourceSubjects compiles exact caller subjects and trusted derived expansion seams.
func validateSourceSubjects(raw sourceConfig) error {
	if len(raw.AllowedSubjects) < 1 || len(raw.AllowedSubjects) > maximumSubjects || len(raw.DerivedSubjects) > maximumSubjects {
		return errConfiguration
	}

	for role, kinds := range raw.AllowedSubjects {
		if !identifierPattern.MatchString(role) || !uniqueIdentifiers(kinds, 6, false) {
			return errConfiguration
		}

		for _, kind := range kinds {
			if !subjectKind(kind) {
				return errConfiguration
			}
		}
	}

	return validateDerivedSubjects(raw)
}

// directKind reports configured admission or derivation of a specific subject kind.
func directKind(roles map[string][]string, kind string) bool {
	for _, kinds := range roles {
		if slices.Contains(kinds, kind) {
			return true
		}
	}

	return false
}

// indexSource rejects principal aliases, mixed binding fields and overlapping registered tuples.
func (c *configuration) indexSource(source *sourcePolicy) error {
	binding := source.config.Binding
	switch binding.Kind {
	case bindingAPI:
		if !validAPIBinding(binding) {
			return errConfiguration
		}

		if _, exists := c.apiSources[binding.CallerPrincipal]; exists {
			return errConfiguration
		}

		c.apiSources[binding.CallerPrincipal] = source

		return nil
	case bindingHost:
		if binding.CallerPrincipal != "" || len(binding.Targets) < 1 || len(binding.Targets) > 16 {
			return errConfiguration
		}

		for _, target := range binding.Targets {
			key, err := bindingExecutionKey(binding, target)
			if err != nil {
				return err
			}

			if _, exists := c.internalSources[key]; exists {
				return errConfiguration
			}

			c.internalSources[key] = source
		}

		return nil
	default:
		return errConfiguration
	}
}

// bindingExecutionKey validates a configured exact target using the shared immutable identity contract.
func bindingExecutionKey(binding sourceBinding, target string) (executionKey, error) {
	parts := strings.Split(target, "/")
	if len(parts) != 2 {
		return executionKey{}, errConfiguration
	}

	identity, err := pluginapi.NewExecutionIdentityView(binding.Module, binding.Component, binding.ExtensionPoint, binding.Operation,
		pluginapi.DecisionTargetSelector{Namespace: parts[0], Action: parts[1]})
	if err != nil {
		return executionKey{}, errConfiguration
	}

	return identityKey(identity), nil
}

// validPrincipal preserves exact case while rejecting incomplete or non-text authentication identities.
func validPrincipal(value string) bool {
	return len(value) > 0 && len(value) <= 512 && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

// sourceForCaller selects only an exact authenticated API principal, without any internal fallback.
func (c *configuration) sourceForCaller(caller pluginapi.DecisionCallerView) *sourcePolicy {
	return c.apiSources[caller.Principal()]
}

// sourceForExecution selects only a registered host callback identity, without inheriting an API caller.
func (c *configuration) sourceForExecution(identity pluginapi.ExecutionIdentityView) *sourcePolicy {
	return c.internalSources[identityKey(identity)]
}

// validProviderReference requires an exact namespace-qualified native provider, never a runtime-selected dependency.
func validProviderReference(value string) bool {
	return pluginapi.ValidateDecisionProviderReference(value) == nil
}

// validSourceLimits requires finite explicit producer rate and fan-out capabilities.
func validSourceLimits(raw sourceConfig) bool {
	return raw.MaximumSubjects >= 1 && raw.MaximumSubjects <= maximumSubjects &&
		raw.RequestsPerSecond >= 1 && raw.RequestsPerSecond <= 10000 && raw.MaxConcurrency >= 1 && raw.MaxConcurrency <= 1024
}

// validateDerivedSubjects confines related-subject expansion to exact IP and a declared ASN provider seam.
func validateDerivedSubjects(raw sourceConfig) error {
	for role, kinds := range raw.DerivedSubjects {
		if !slices.Contains(raw.AllowedSubjects[role], kindIP) || !uniqueIdentifiers(kinds, 2, false) {
			return errConfiguration
		}

		for _, kind := range kinds {
			if kind != kindNetwork && kind != kindASN {
				return errConfiguration
			}
		}
	}

	if directKind(raw.DerivedSubjects, kindASN) {
		if !validProviderReference(raw.ASNProvider) || !validExtractorAttribute(raw.ASNFact) || !strings.HasPrefix(raw.ASNFact, asnProviderFactPrefix(raw.ASNProvider)) || raw.ASNMaxAge == "" {
			return errConfiguration
		}
	} else if raw.ASNProvider != "" || raw.ASNFact != "" || raw.ASNMaxAge != "" {
		return errConfiguration
	}

	return nil
}

// validAPIBinding excludes every host-execution field from an authenticated principal binding.
func validAPIBinding(binding sourceBinding) bool {
	return validPrincipal(binding.CallerPrincipal) && binding.Module == "" && binding.Component == "" &&
		binding.ExtensionPoint == "" && binding.Operation == "" && len(binding.Targets) == 0
}
