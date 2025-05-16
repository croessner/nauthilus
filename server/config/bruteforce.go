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
	SoftWhitelist     `mapstructure:"soft_whitelist"`
	IPWhitelist       []string         `mapstructure:"ip_whitelist" validate:"omitempty,dive,ip_addr|cidr"`
	Buckets           []BruteForceRule `mapstructure:"buckets" validate:"required,dive"`
	Learning          []*Feature       `mapstructure:"learning" validate:"omitempty,dive"`
	ToleratePercent   uint8            `mapstructure:"tolerate_percent" validate:"omitempty,min=0,max=100"`
	CustomTolerations []Tolerate       `mapstructure:"custom_tolerations" validate:"omitempty,dive"`
	TolerateTTL       time.Duration    `mapstructure:"tolerate_ttl" validate:"omitempty,gt=0,max=8760h"`
	NeuralNetwork     NeuralNetwork    `mapstructure:"neural_network" validate:"omitempty"`
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

// GetCustomTolerations returns the CustomTolerations slice from the BruteForceSection. Returns nil if the receiver is nil.
func (b *BruteForceSection) GetCustomTolerations() []Tolerate {
	if b == nil {
		return nil
	}

	return b.CustomTolerations
}

// GetNeuralNetwork retrieves a pointer to the NeuralNetwork configuration from the ServerSection instance.
func (s *BruteForceSection) GetNeuralNetwork() *NeuralNetwork {
	return &s.NeuralNetwork
}

// Tolerate represents a configuration item for toleration settings based on IP, percentage, and Time-to-Live (TTL).
type Tolerate struct {
	IPAddress       string        `mapstructure:"ip_address" validate:"required,ip_addr|cidr"`
	ToleratePercent uint8         `mapstructure:"tolerate_percent" validate:"required,min=0,max=100"`
	TolerateTTL     time.Duration `mapstructure:"tolerate_ttl" validate:"required,gt=0,max=8760h"`
}

// BruteForceRule is the definition of a brute force rule as defined in the configuration file. See the markdown
// documentation for a description of the field names.
type BruteForceRule struct {
	Name           string        `mapstructure:"name" validate:"required"`
	Period         time.Duration `mapstructure:"period" validate:"required,gt=0,max=8760h"`
	CIDR           uint          `mapstructure:"cidr" validate:"required,min=1,max=128"`
	IPv4           bool
	IPv6           bool
	FailedRequests uint `mapstructure:"failed_requests" validate:"required,min=1"`
}

func (b *BruteForceRule) String() string {
	if b == nil {
		return "<nil>"
	}

	return fmt.Sprintf("Name: %s, Period: %s, CIDR: %d, IPv4: %t, IPv6: %t, FailedRequests: %d", b.Name, b.Period, b.CIDR, b.IPv4, b.IPv6, b.FailedRequests)
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
	return n.MaxTrainingRecords
}

// GetStaticWeight retrieves the weight for static rules in the weighted decision.
// Returns 0.4 as default if not set.
func (n *NeuralNetwork) GetStaticWeight() float64 {
	if n.StaticWeight == 0 {
		return 0.4 // Default value
	}

	return n.StaticWeight
}

// GetMLWeight retrieves the weight for ML in the weighted decision.
// Returns 0.6 as default if not set.
func (n *NeuralNetwork) GetMLWeight() float64 {
	if n.MLWeight == 0 {
		return 0.6 // Default value
	}

	return n.MLWeight
}

// GetThreshold retrieves the threshold for the weighted decision.
// Returns 0.7 as default if not set.
func (n *NeuralNetwork) GetThreshold() float64 {
	if n.Threshold == 0 {
		return 0.7 // Default value
	}

	return n.Threshold
}

// GetLearningRate retrieves the learning rate for the neural network.
// Returns 0.01 as default if not set.
func (n *NeuralNetwork) GetLearningRate() float64 {
	if n.LearningRate == 0 {
		return 0.01 // Default value
	}

	return n.LearningRate
}
