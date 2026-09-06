package main

import (
	"slices"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type admissionSnapshot struct {
	Targets []admissionTargetConfig `mapstructure:"targets"`
	Clients []admissionClientConfig `mapstructure:"clients"`
	Enabled bool                    `mapstructure:"enabled"`
}

type admissionClientConfig struct {
	Targets           []string `mapstructure:"targets"`
	Schemas           []string `mapstructure:"schemas"`
	Principal         string   `mapstructure:"principal"`
	MaxConcurrency    int      `mapstructure:"max_concurrency"`
	RequestsPerSecond int      `mapstructure:"requests_per_second"`
	Diagnostics       bool     `mapstructure:"diagnostics"`
}

// validateStartup matches registered sources to the host-owned admission and callback snapshots.
func (c *configuration) validateStartup(view pluginapi.ConfigView, registered map[executionKey]struct{}) error {
	if view == nil {
		return errConfiguration
	}

	if len(c.apiSources) > 0 {
		var admission admissionSnapshot
		if err := view.Sub("policy_admission").Decode(&admission); err != nil || !admission.Enabled {
			return errConfiguration
		}

		if err := validateObservationTarget(admission); err != nil {
			return err
		}

		if err := c.validateAdmission(admission); err != nil {
			return err
		}
	}

	for identity := range c.internalSources {
		module, exists := view.Get("host_context.module_name")
		if !exists || module != identity.module {
			return errConfiguration
		}

		if _, exists := registered[identity]; !exists {
			return errConfiguration
		}
	}

	return nil
}

// validateAdmission requires one exact principal grant with transport limits no broader than the source policy.
func (c *configuration) validateAdmission(admission admissionSnapshot) error {
	profiles := make(map[string]admissionClientConfig, len(admission.Clients))
	for _, profile := range admission.Clients {
		if _, exists := profiles[profile.Principal]; exists {
			return errConfiguration
		}

		profiles[profile.Principal] = profile
	}

	for principal, source := range c.apiSources {
		profile, exists := profiles[principal]
		if !exists || !validAdmissionGrant(profile, source) {
			return errConfiguration
		}
	}

	return nil
}

// validAdmissionGrant ensures transport authority remains within the source policy's exact grant and limits.
func validAdmissionGrant(profile admissionClientConfig, source *sourcePolicy) bool {
	return slices.Contains(profile.Targets, "reputation/observe") &&
		(len(profile.Schemas) == 0 || slices.Contains(profile.Schemas, "reputation/observe/v1")) && !profile.Diagnostics &&
		profile.MaxConcurrency >= 1 && profile.MaxConcurrency <= source.config.MaxConcurrency &&
		profile.RequestsPerSecond >= 1 && profile.RequestsPerSecond <= source.config.RequestsPerSecond
}

// admissionTargetConfig contains only the host's exact activation contract, never Policy expressions or credentials.
type admissionTargetConfig struct {
	Target  string `mapstructure:"target"`
	Schema  string `mapstructure:"schema"`
	Mode    string `mapstructure:"mode"`
	NoMatch string `mapstructure:"no_match"`
}

// validateObservationTarget prevents a producer endpoint from silently skipping its selected storage effects.
func validateObservationTarget(snapshot admissionSnapshot) error {
	matches := 0

	for _, target := range snapshot.Targets {
		if target.Target != "reputation/observe" {
			continue
		}

		matches++

		if target.Schema != "reputation/observe/v1" || target.Mode != "enforce" || target.NoMatch != "deny" {
			return errConfiguration
		}
	}

	if matches != 1 {
		return errConfiguration
	}

	return nil
}
