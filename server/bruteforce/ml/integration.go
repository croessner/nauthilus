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

package ml

import (
	"context"
	"fmt"
	"net"

	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/go-kit/log/level"
)

// MLBucketManager extends the standard BucketManager with machine learning capabilities
type MLBucketManager struct {
	bruteforce.BucketManager
	mlDetector         *BruteForceMLDetector
	ctx                context.Context
	guid               string
	clientIP           string
	username           string
	password           string
	threshold          float64
	additionalFeatures map[string]any
}

// NewMLBucketManager creates a new bucket manager with ML capabilities
func NewMLBucketManager(ctx context.Context, guid, clientIP string) bruteforce.BucketManager {
	// Create the standard bucket manager
	standardBM := bruteforce.NewBucketManager(ctx, guid, clientIP)

	// Create our ML-enhanced bucket manager
	mlBM := &MLBucketManager{
		BucketManager: standardBM,
		ctx:           ctx,
		guid:          guid,
		clientIP:      clientIP,
		threshold:     0.7, // Default threshold, could be configurable
	}

	return mlBM
}

// WithUsername sets the username and initializes the ML detector
func (m *MLBucketManager) WithUsername(username string) bruteforce.BucketManager {
	m.username = username
	m.BucketManager = m.BucketManager.WithUsername(username)

	// Initialize ML detector if we have both username and clientIP
	if m.username != "" && m.clientIP != "" && m.mlDetector == nil {
		// Use the singleton pattern to get the detector
		m.mlDetector = GetBruteForceMLDetector(m.ctx, m.guid, m.clientIP, m.username)

		// Pass any additional features to the detector
		if m.additionalFeatures != nil {
			m.mlDetector.SetAdditionalFeatures(m.additionalFeatures)
		}
	}

	return m
}

// WithPassword sets the password for the bucket manager
func (m *MLBucketManager) WithPassword(password string) bruteforce.BucketManager {
	m.password = password
	m.BucketManager = m.BucketManager.WithPassword(password)

	return m
}

// WithAdditionalFeatures sets additional features for the bucket manager
func (m *MLBucketManager) WithAdditionalFeatures(features map[string]any) bruteforce.BucketManager {
	m.additionalFeatures = features
	m.BucketManager = m.BucketManager.WithAdditionalFeatures(features)

	return m
}

// CheckBucketOverLimit enhances the standard bucket check with ML-based detection
func (m *MLBucketManager) CheckBucketOverLimit(rules []config.BruteForceRule, network **net.IPNet, message *string) (withError bool, ruleTriggered bool, ruleNumber int) {
	// First, check with the standard rule-based approach
	withError, ruleTriggered, ruleNumber = m.BucketManager.CheckBucketOverLimit(rules, network, message)

	// If the standard check didn't trigger, try the ML-based detection
	if !ruleTriggered && !withError && m.mlDetector != nil {
		isBruteForce, probability, err := m.mlDetector.Predict()
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, m.guid,
				definitions.LogKeyMsg, fmt.Sprintf("ML prediction error: %v", err),
			)

			return false, false, 0
		}

		if isBruteForce {
			ruleTriggered = true
			*message = fmt.Sprintf("ML-based brute force detection triggered (probability: %.2f)", probability)

			level.Info(log.Logger).Log(
				definitions.LogKeyGUID, m.guid,
				definitions.LogKeyBruteForce, *message,
				definitions.LogKeyUsername, m.username,
				definitions.LogKeyClientIP, m.clientIP,
				"probability", probability,
			)

			// Use the first rule for processing
			if len(rules) > 0 {
				ruleNumber = 0
			}
		}
	}

	return withError, ruleTriggered, ruleNumber
}

// ProcessBruteForce handles the result of brute force detection
func (m *MLBucketManager) ProcessBruteForce(ruleTriggered, alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet, message string, setter func()) bool {
	// Record the login attempt for future ML training
	if m.mlDetector != nil {
		features, err := m.mlDetector.CollectFeatures()
		if err == nil {
			// Record as a failed login if brute force was detected
			success := !(ruleTriggered || alreadyTriggered)
			// Use the standalone RecordLoginResult function instead of the method
			_ = RecordLoginResult(m.ctx, success, features)
		}
	}

	// Use the standard processing
	return m.BucketManager.ProcessBruteForce(ruleTriggered, alreadyTriggered, rule, network, message, setter)
}

// Close cleans up resources when the MLBucketManager is no longer needed
// This is a no-op since we're using a global ML system
func (m *MLBucketManager) Close() {
	// No-op - the ML system is managed globally and will be cleaned up by ShutdownMLSystem
}

// TrainModel manually triggers training of the ML model
func (m *MLBucketManager) TrainModel(maxSamples, epochs int) error {
	// Ensure the ML system is initialized
	if globalTrainer == nil {
		if err := InitMLSystem(m.ctx); err != nil {
			return fmt.Errorf("failed to initialize ML system: %w", err)
		}
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyGUID, m.guid,
		definitions.LogKeyMsg, fmt.Sprintf("Manually triggering ML model training with %d samples for %d epochs", maxSamples, epochs),
	)

	// Use the global trainer instead of the detector
	err := globalTrainer.TrainWithStoredData(maxSamples, epochs)
	if err != nil {
		return err
	}

	// Save the trained model to Redis
	return globalTrainer.SaveModelToRedis()
}

// RecordLoginFeature records a login feature for ML training
func (m *MLBucketManager) RecordLoginFeature() {
	// Record the login attempt for future ML training
	if m.mlDetector != nil {
		features, err := m.mlDetector.CollectFeatures()
		if err == nil {
			// This is a triggered feature, so it's a failed login
			_ = RecordLoginResult(m.ctx, false, features)
		}
	}
}

// RecordSuccessfulLogin records a successful login for ML training
func (m *MLBucketManager) RecordSuccessfulLogin() {
	// Record the login attempt for future ML training
	if m.mlDetector != nil {
		features, err := m.mlDetector.CollectFeatures()
		if err == nil {
			// This is a successful login
			_ = RecordLoginResult(m.ctx, true, features)
		}
	}
}

// How to use the ML-enhanced bucket manager:
//
// 1. Replace the standard bucket manager creation with the ML version:
//
//    // Instead of:
//    // bm := bruteforce.NewBucketManager(ctx, guid, clientIP)
//
//    // Use:
//    bm := ml.NewMLBucketManager(ctx, guid, clientIP)
//
// 2. The rest of the code remains the same, as the ML-enhanced version
//    implements the same BucketManager interface
//
// 3. To add additional features for the ML system, use the WithAdditionalFeatures method:
//
//    // Create a map of additional features
//    additionalFeatures := map[string]any{
//        "geo_country": "DE",
//        "geo_city": "Berlin",
//        "device_type": "mobile",
//        "connection_type": "4G",
//    }
//
//    // Add the features to the bucket manager
//    bm = bm.WithAdditionalFeatures(additionalFeatures)
//
//    // These features will be stored in the LoginFeatures struct and can be used
//    // for future model improvements or other purposes.
