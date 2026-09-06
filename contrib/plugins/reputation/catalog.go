package main

import "time"

type signalConfig struct {
	SubjectRoles   map[string]map[string]float64 `mapstructure:"subject_roles"`
	SourceClasses  []string                      `mapstructure:"source_classes"`
	Profiles       []string                      `mapstructure:"profiles"`
	MagnitudeRange []float64                     `mapstructure:"magnitude_range"`
	Direction      string                        `mapstructure:"direction"`
	Magnitude      string                        `mapstructure:"magnitude"`
	EvidenceOrigin string                        `mapstructure:"evidence_origin"`
	MaxEventAge    string                        `mapstructure:"max_event_age"`
	Weight         float64                       `mapstructure:"weight"`
	Authoritative  bool                          `mapstructure:"authoritative"`
}

type signalPolicy struct {
	config signalConfig
	name   string
	maxAge time.Duration
}

// compileSignals closes signal semantics and profile eligibility before any source is admitted.
func (c *configuration) compileSignals() error {
	if len(c.raw.Signals) < 1 || len(c.raw.Signals) > 64 {
		return errConfiguration
	}

	c.signals = make(map[string]*signalPolicy, len(c.raw.Signals))
	for name, raw := range c.raw.Signals {
		if !identifierPattern.MatchString(name) {
			return errConfiguration
		}

		age, err := durationBound(raw.MaxEventAge, c.retention, false)
		if err != nil {
			return err
		}

		if err := c.validateSignal(raw); err != nil {
			return err
		}

		c.signals[name] = &signalPolicy{config: raw, name: name, maxAge: age}
	}

	return nil
}

// validateSignal rejects caller-defined causality, unbounded weights and undeclared accumulator dimensions.
func (c *configuration) validateSignal(raw signalConfig) error {
	if (raw.Direction != directionTrust && raw.Direction != directionRisk) || !positiveBound(raw.Weight, 1000) {
		return errConfiguration
	}

	if !validSignalOrigin(raw) {
		return errConfiguration
	}

	if !uniqueIdentifiers(raw.SourceClasses, 8, false) || !uniqueIdentifiers(raw.Profiles, 3, false) {
		return errConfiguration
	}

	if err := c.validateSignalDimensions(raw); err != nil {
		return err
	}

	if err := validateMagnitudePolicy(raw); err != nil {
		return err
	}

	return validateRoleMultipliers(raw.SubjectRoles)
}

// validateMagnitudePolicy requires explicit producer-measurement semantics within zero and one.
func validateMagnitudePolicy(raw signalConfig) error {
	if raw.Magnitude == magnitudeForbidden {
		if len(raw.MagnitudeRange) != 0 {
			return errConfiguration
		}

		return nil
	}

	if raw.Magnitude != magnitudeOptional && raw.Magnitude != magnitudeRequired {
		return errConfiguration
	}

	if len(raw.MagnitudeRange) != 2 || !nonnegativeBound(raw.MagnitudeRange[0], 1) ||
		!nonnegativeBound(raw.MagnitudeRange[1], 1) || raw.MagnitudeRange[0] > raw.MagnitudeRange[1] {
		return errConfiguration
	}

	return nil
}

// validateRoleMultipliers binds each semantic role to explicitly weighted subject kinds.
func validateRoleMultipliers(roles map[string]map[string]float64) error {
	if len(roles) < 1 || len(roles) > maximumSubjects {
		return errConfiguration
	}

	for role, kinds := range roles {
		if !identifierPattern.MatchString(role) || len(kinds) < 1 || len(kinds) > 6 {
			return errConfiguration
		}

		for kind, weight := range kinds {
			if !subjectKind(kind) || !positiveBound(weight, 1) {
				return errConfiguration
			}
		}
	}

	return nil
}

// validateSignalDimensions binds signal source classes and decay profiles to configured accumulators.
func (c *configuration) validateSignalDimensions(raw signalConfig) error {
	for _, class := range raw.SourceClasses {
		if _, ok := c.raw.SourceClassCaps[class]; !ok {
			return errConfiguration
		}
	}

	for _, profile := range raw.Profiles {
		if _, ok := c.profiles[profile]; !ok {
			return errConfiguration
		}
	}

	return nil
}

// validSignalOrigin closes evidence origin and confines authoritative blocking eligibility to independent risk feeds.
func validSignalOrigin(raw signalConfig) bool {
	if raw.EvidenceOrigin != originExternal && raw.EvidenceOrigin != originBackend && raw.EvidenceOrigin != originAuthoritative {
		return false
	}

	return !raw.Authoritative || (raw.EvidenceOrigin == originAuthoritative && raw.Direction == directionRisk)
}
