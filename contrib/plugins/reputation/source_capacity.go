package main

import pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"

type sourceAdmissionCapacity struct {
	RequestsPerSecond int `mapstructure:"requests_per_second"`
	MaxConcurrency    int `mapstructure:"max_concurrency"`
}

// validateSourceAdmissionCapacity rejects unknown sources and changes outside the host's bounded admission contract.
func (c *configuration) validateSourceAdmissionCapacity() error {
	for name, capacity := range c.raw.SourceAdmissionCapacity {
		source, exists := c.raw.Sources[name]
		if !exists {
			return errConfiguration
		}

		limits := pluginapi.CallbackAdmissionLimits{RequestsPerSecond: capacity.RequestsPerSecond, MaxConcurrency: capacity.MaxConcurrency}
		if err := limits.Validate(); err != nil || limits.RequestsPerSecond < source.RequestsPerSecond || limits.MaxConcurrency < source.MaxConcurrency {
			return errConfiguration
		}
	}

	return nil
}

// admissionLimits resolves operational headroom while leaving the fingerprinted source grant unchanged.
func (s *sourcePolicy) admissionLimits() pluginapi.CallbackAdmissionLimits {
	return pluginapi.CallbackAdmissionLimits{
		RequestsPerSecond: max(s.config.RequestsPerSecond, s.capacity.RequestsPerSecond),
		MaxConcurrency:    max(s.config.MaxConcurrency, s.capacity.MaxConcurrency),
	}
}
