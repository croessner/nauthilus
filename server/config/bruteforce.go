// Copyright (C) 2024 Christian Rößner
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
	"fmt"
	"time"
)

type BruteForceSection struct {
	SoftWhitelist      `mapstructure:"soft_whitelist"`
	IPWhitelist        []string         `mapstructure:"ip_whitelist" validate:"omitempty,dive,ip_addr|cidr"`
	Buckets            []BruteForceRule `mapstructure:"buckets" validate:"required,dive"`
	Learning           []*Feature       `mapstructure:"learning" validate:"omitempty,dive"`
	ToleratePercent    uint8            `mapstructure:"tolerate_percent" validate:"omitempty,min=0,max=100"`
	CustomTolerations  []Tolerate       `mapstructure:"custom_tolerations" validate:"omitempty,dive"`
	TolerateTTL        time.Duration    `mapstructure:"tolerate_ttl" validate:"omitempty,gt=0,max=8760h"`
	AdaptiveToleration bool             `mapstructure:"adaptive_toleration"`
	MinToleratePercent uint8            `mapstructure:"min_tolerate_percent" validate:"omitempty,min=0,max=100"`
	MaxToleratePercent uint8            `mapstructure:"max_tolerate_percent" validate:"omitempty,min=0,max=100"`
	ScaleFactor        float64          `mapstructure:"scale_factor" validate:"omitempty,min=0.1,max=10"`
	NeuralNetwork      NeuralNetwork    `mapstructure:"neural_network" validate:"omitempty"`
}

func (b *BruteForceSection) String() string {
	if b == nil {
		return "<nil>"
	}

	return fmt.Sprintf("Buckets: %+v, IP-Whitelist: %+v", b.Buckets, b.IPWhitelist)
}

// LearnFromFeature checks if the given feature is present in the Learning slice of the BruteForceSection.
// It returns true if the feature is found, otherwise false.
func (b *BruteForceSection) LearnFromFeature(input string) bool {
	if b == nil {
		return false
	}

	if b.Learning == nil {
		return false
	}

	if len(b.Learning) == 0 {
		return false
	}

	for _, feature := range b.Learning {
		if input == feature.Get() {
			return true
		}
	}

	return false
}

// GetToleratePercent retrieves the ToleratePercent value from the BruteForceSection instance. Returns 0 if the receiver is nil.
func (b *BruteForceSection) GetToleratePercent() uint8 {
	if b == nil {
		return 0
	}

	return b.ToleratePercent
}

// GetTolerateTTL retrieves the TolerateTTL value from the BruteForceSection instance. Returns 0 if the receiver is nil.
func (b *BruteForceSection) GetTolerateTTL() time.Duration {
	if b == nil {
		return 0
	}

	return b.TolerateTTL
}

// GetCustomTolerations returns the CustomTolerations slice from the BruteForceSection. Returns an empty slice if the receiver is nil.
func (b *BruteForceSection) GetCustomTolerations() []Tolerate {
	if b == nil {
		return []Tolerate{}
	}

	return b.CustomTolerations
}

// GetAdaptiveToleration retrieves the AdaptiveToleration value from the BruteForceSection instance.
// Returns false if the receiver is nil.
func (b *BruteForceSection) GetAdaptiveToleration() bool {
	if b == nil {
		return false
	}

	return b.AdaptiveToleration
}

// GetMinToleratePercent retrieves the MinToleratePercent value from the BruteForceSection instance.
// Returns 10 as default if not set or if the receiver is nil.
func (b *BruteForceSection) GetMinToleratePercent() uint8 {
	if b == nil {
		return 10
	}

	if b.MinToleratePercent == 0 {
		return 10 // Default value
	}

	return b.MinToleratePercent
}

// GetMaxToleratePercent retrieves the MaxToleratePercent value from the BruteForceSection instance.
// Returns 50 as default if not set or if the receiver is nil.
func (b *BruteForceSection) GetMaxToleratePercent() uint8 {
	if b == nil {
		return 50
	}

	if b.MaxToleratePercent == 0 {
		return 50 // Default value
	}

	return b.MaxToleratePercent
}

// GetScaleFactor retrieves the ScaleFactor value from the BruteForceSection instance.
// Returns 1.0 as default if not set or if the receiver is nil.
func (b *BruteForceSection) GetScaleFactor() float64 {
	if b == nil {
		return 1.0
	}

	if b.ScaleFactor == 0 {
		return 1.0 // Default value
	}

	return b.ScaleFactor
}

// GetSoftWhitelist retrieves the SoftWhitelist from the BruteForceSection.
// Returns an empty map if the BruteForceSection is nil.
func (b *BruteForceSection) GetSoftWhitelist() SoftWhitelist {
	if b == nil {
		return map[string][]string{}
	}

	return b.SoftWhitelist
}

// GetIPWhitelist retrieves the IP whitelist from the BruteForceSection.
// Returns an empty slice if the BruteForceSection is nil.
func (b *BruteForceSection) GetIPWhitelist() []string {
	if b == nil {
		return []string{}
	}

	return b.IPWhitelist
}

// GetNeuralNetwork retrieves a pointer to the NeuralNetwork configuration from the ServerSection instance.
// Returns an empty NeuralNetwork if the BruteForceSection is nil.
func (s *BruteForceSection) GetNeuralNetwork() *NeuralNetwork {
	if s == nil {
		return &NeuralNetwork{}
	}

	return &s.NeuralNetwork
}

// GetBuckets retrieves the list of brute force rules from the BruteForceSection.
// Returns an empty slice if the BruteForceSection is nil.
func (b *BruteForceSection) GetBuckets() []BruteForceRule {
	if b == nil {
		return []BruteForceRule{}
	}

	return b.Buckets
}

// Tolerate represents a configuration item for toleration settings based on IP, percentage, and Time-to-Live (TTL).
type Tolerate struct {
	IPAddress          string        `mapstructure:"ip_address" validate:"required,ip_addr|cidr"`
	ToleratePercent    uint8         `mapstructure:"tolerate_percent" validate:"required,min=0,max=100"`
	TolerateTTL        time.Duration `mapstructure:"tolerate_ttl" validate:"required,gt=0,max=8760h"`
	AdaptiveToleration bool          `mapstructure:"adaptive_toleration"`
	MinToleratePercent uint8         `mapstructure:"min_tolerate_percent" validate:"omitempty,min=0,max=100"`
	MaxToleratePercent uint8         `mapstructure:"max_tolerate_percent" validate:"omitempty,min=0,max=100"`
	ScaleFactor        float64       `mapstructure:"scale_factor" validate:"omitempty,min=0.1,max=10"`
}

// GetIPAddress retrieves the IP address from the Tolerate configuration.
// Returns an empty string if the Tolerate is nil.
func (t *Tolerate) GetIPAddress() string {
	if t == nil {
		return ""
	}

	return t.IPAddress
}

// GetToleratePercent retrieves the tolerate percent value from the Tolerate configuration.
// Returns 0 if the Tolerate is nil.
func (t *Tolerate) GetToleratePercent() uint8 {
	if t == nil {
		return 0
	}

	return t.ToleratePercent
}

// GetTolerateTTL retrieves the tolerate TTL duration from the Tolerate configuration.
// Returns 0 if the Tolerate is nil.
func (t *Tolerate) GetTolerateTTL() time.Duration {
	if t == nil {
		return 0
	}

	return t.TolerateTTL
}

// GetAdaptiveToleration checks if adaptive toleration is enabled in the Tolerate configuration.
// Returns false if the Tolerate is nil.
func (t *Tolerate) GetAdaptiveToleration() bool {
	if t == nil {
		return false
	}

	return t.AdaptiveToleration
}

// GetMinToleratePercent retrieves the minimum tolerate percent value from the Tolerate configuration.
// Returns 10 as default if not set or if the Tolerate is nil.
func (t *Tolerate) GetMinToleratePercent() uint8 {
	if t == nil {
		return 10
	}

	if t.MinToleratePercent == 0 {
		return 10 // Default value
	}

	return t.MinToleratePercent
}

// GetMaxToleratePercent retrieves the maximum tolerate percent value from the Tolerate configuration.
// Returns 50 as default if not set or if the Tolerate is nil.
func (t *Tolerate) GetMaxToleratePercent() uint8 {
	if t == nil {
		return 50
	}

	if t.MaxToleratePercent == 0 {
		return 50 // Default value
	}

	return t.MaxToleratePercent
}

// GetScaleFactor retrieves the scale factor value from the Tolerate configuration.
// Returns 1.0 as default if not set or if the Tolerate is nil.
func (t *Tolerate) GetScaleFactor() float64 {
	if t == nil {
		return 1.0
	}

	if t.ScaleFactor == 0 {
		return 1.0 // Default value
	}

	return t.ScaleFactor
}

// BruteForceRule is the definition of a brute force rule as defined in the configuration file. See the markdown
// documentation for a description of the field names.
type BruteForceRule struct {
	Name             string        `mapstructure:"name" validate:"required"`
	Period           time.Duration `mapstructure:"period" validate:"required,gt=0,max=8760h"`
	CIDR             uint          `mapstructure:"cidr" validate:"required,min=1,max=128"`
	IPv4             bool
	IPv6             bool
	FailedRequests   uint     `mapstructure:"failed_requests" validate:"required,min=1"`
	FilterByProtocol []string `mapstructure:"filter_by_protocol" validate:"omitempty"`
	FilterByOIDCCID  []string `mapstructure:"filter_by_oidc_cid" validate:"omitempty"`
}

func (b *BruteForceRule) String() string {
	if b == nil {
		return "<nil>"
	}

	return fmt.Sprintf("Name: %s, Period: %s, CIDR: %d, IPv4: %t, IPv6: %t, FailedRequests: %d", b.Name, b.Period, b.CIDR, b.IPv4, b.IPv6, b.FailedRequests)
}

// GetName retrieves the name of the brute force rule.
// Returns an empty string if the BruteForceRule is nil.
func (b *BruteForceRule) GetName() string {
	if b == nil {
		return ""
	}

	return b.Name
}

// GetPeriod retrieves the period duration for the brute force rule.
// Returns 0 if the BruteForceRule is nil.
func (b *BruteForceRule) GetPeriod() time.Duration {
	if b == nil {
		return 0
	}

	return b.Period
}

// GetCIDR retrieves the CIDR value for the brute force rule.
// Returns 0 if the BruteForceRule is nil.
func (b *BruteForceRule) GetCIDR() uint {
	if b == nil {
		return 0
	}

	return b.CIDR
}

// IsIPv4 checks if the brute force rule is configured for IPv4.
// Returns false if the BruteForceRule is nil.
func (b *BruteForceRule) IsIPv4() bool {
	if b == nil {
		return false
	}

	return b.IPv4
}

// IsIPv6 checks if the brute force rule is configured for IPv6.
// Returns false if the BruteForceRule is nil.
func (b *BruteForceRule) IsIPv6() bool {
	if b == nil {
		return false
	}

	return b.IPv6
}

// GetFailedRequests retrieves the number of failed requests threshold for the brute force rule.
// Returns 0 if the BruteForceRule is nil.
func (b *BruteForceRule) GetFailedRequests() uint {
	if b == nil {
		return 0
	}

	return b.FailedRequests
}

// GetFilterByProtocol retrieves the list of protocols to filter by for the brute force rule.
// Returns an empty slice if the BruteForceRule is nil.
func (b *BruteForceRule) GetFilterByProtocol() []string {
	if b == nil {
		return []string{}
	}

	return b.FilterByProtocol
}

// GetFilterByOIDCCID retrieves the list of OIDC client IDs to filter by for the brute force rule.
// Returns an empty slice if the BruteForceRule is nil.
func (b *BruteForceRule) GetFilterByOIDCCID() []string {
	if b == nil {
		return []string{}
	}

	return b.FilterByOIDCCID
}

// NeuralNetwork represents the configuration for the neural network machine learning system.
type NeuralNetwork struct {
	MaxTrainingRecords int32   `mapstructure:"max_training_records" validate:"omitempty,gte=1000,lte=100000"`
	HiddenNeurons      int     `mapstructure:"hidden_neurons" validate:"omitempty,min=8,max=20"`
	ActivationFunction string  `mapstructure:"activation_function" validate:"omitempty,oneof=sigmoid tanh relu leaky_relu"`
	StaticWeight       float64 `mapstructure:"static_weight" validate:"omitempty,min=0,max=1"`
	MLWeight           float64 `mapstructure:"ml_weight" validate:"omitempty,min=0,max=1"`
	Threshold          float64 `mapstructure:"threshold" validate:"omitempty,min=0,max=1"`
	LearningRate       float64 `mapstructure:"learning_rate" validate:"omitempty,min=0.001,max=0.1"`
}

// GetMaxTrainingRecords retrieves the maximum number of training records to keep for the neural network.
func (n *NeuralNetwork) GetMaxTrainingRecords() int32 {
	if n == nil {
		return 10000 // Default value
	}

	return n.MaxTrainingRecords
}

// GetStaticWeight retrieves the weight for static rules in the weighted decision.
// Returns 0.4 as default if not set.
func (n *NeuralNetwork) GetStaticWeight() float64 {
	if n == nil || n.StaticWeight == 0 {
		return 0.4 // Default value
	}

	return n.StaticWeight
}

// GetMLWeight retrieves the weight for ML in the weighted decision.
// Returns 0.6 as default if not set.
func (n *NeuralNetwork) GetMLWeight() float64 {
	if n == nil || n.MLWeight == 0 {
		return 0.6 // Default value
	}

	return n.MLWeight
}

// GetThreshold retrieves the threshold for the weighted decision.
// Returns 0.7 as default if not set.
func (n *NeuralNetwork) GetThreshold() float64 {
	if n == nil || n.Threshold == 0 {
		return 0.7 // Default value
	}

	return n.Threshold
}

// GetLearningRate retrieves the learning rate for the neural network.
// Returns 0.01 as default if not set.
func (n *NeuralNetwork) GetLearningRate() float64 {
	if n == nil || n.LearningRate == 0 {
		return 0.01 // Default value
	}

	return n.LearningRate
}
