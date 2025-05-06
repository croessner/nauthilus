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
	"github.com/croessner/nauthilus/server/util"
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
	noAuth             bool
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
		threshold:     0.7,   // Default threshold, could be configurable
		noAuth:        false, // Default to false, will be set by the caller if needed
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

	// If the mlDetector is already initialized, pass the features to it
	if m.mlDetector != nil {
		m.mlDetector.SetAdditionalFeatures(features)
	}

	return m
}

// SetNoAuth sets the NoAuth flag for the bucket manager
func (m *MLBucketManager) SetNoAuth(noAuth bool) {
	m.noAuth = noAuth
}

// CheckBucketOverLimit enhances the standard bucket check with ML-based detection
func (m *MLBucketManager) CheckBucketOverLimit(rules []config.BruteForceRule, network **net.IPNet, message *string) (withError bool, ruleTriggered bool, ruleNumber int) {
	// First, check with the standard rule-based approach
	withError, ruleTriggered, ruleNumber = m.BucketManager.CheckBucketOverLimit(rules, network, message)

	// If the standard check didn't trigger, try the ML-based detection
	if !ruleTriggered && !withError && m.mlDetector != nil {
		// Log the state of static bucket system before ML prediction
		util.DebugModule(definitions.DbgNeural,
			"action", "pre_ml_prediction",
			"static_rule_triggered", ruleTriggered,
			"static_error", withError,
			definitions.LogKeyGUID, m.guid,
		)

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

			// Log the state after ML prediction
			util.DebugModule(definitions.DbgNeural,
				"action", "post_ml_prediction",
				"static_rule_triggered", false, // It was false before ML prediction
				"ml_rule_triggered", true,
				"final_rule_triggered", ruleTriggered,
				"probability", probability,
				"probability_percent", fmt.Sprintf("%.2f%%", probability*100),
				definitions.LogKeyGUID, m.guid,
			)

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
		} else {
			// Log the state after ML prediction when no brute force is detected
			util.DebugModule(definitions.DbgNeural,
				"action", "post_ml_prediction",
				"static_rule_triggered", false, // It was false before ML prediction
				"ml_rule_triggered", false,
				"final_rule_triggered", ruleTriggered,
				"probability", probability,
				"probability_percent", fmt.Sprintf("%.2f%%", probability*100),
				definitions.LogKeyGUID, m.guid,
			)
		}
	}

	return withError, ruleTriggered, ruleNumber
}

// ProcessBruteForce handles the result of brute force detection
func (m *MLBucketManager) ProcessBruteForce(ruleTriggered, alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet, message string, setter func()) bool {
	// Always run the ML detector for all login attempts, not just when static rules trigger
	if m.mlDetector != nil {
		// First, collect features for ML processing
		features, err := m.mlDetector.CollectFeatures()
		if err == nil {
			// Only record as a failed login if a rule was triggered
			if ruleTriggered || alreadyTriggered {
				util.DebugModule(definitions.DbgNeural,
					"action", "record_login_attempt",
					"guid", m.guid,
					"client_ip", m.clientIP,
					"username", m.username,
					"additional_features", fmt.Sprintf("%+v", features.AdditionalFeatures),
				)

				_ = RecordLoginResult(m.ctx, false, features, m.clientIP, m.username, m.guid)
			}

			// If static rules haven't triggered, check if ML detector would trigger
			if !ruleTriggered && !alreadyTriggered {
				// Log the state before ML prediction
				util.DebugModule(definitions.DbgNeural,
					"action", "process_pre_ml_prediction",
					"rule_triggered", ruleTriggered,
					"already_triggered", alreadyTriggered,
					definitions.LogKeyGUID, m.guid,
				)

				isBruteForce, probability, predErr := m.mlDetector.Predict()
				if predErr == nil && isBruteForce {
					// ML detector has detected a brute force attack
					ruleTriggered = true
					message = fmt.Sprintf("ML-based brute force detection triggered (probability: %.2f)", probability)

					// Log the state after ML prediction
					util.DebugModule(definitions.DbgNeural,
						"action", "process_post_ml_prediction",
						"static_rule_triggered", false, // It was false before ML prediction
						"already_triggered", alreadyTriggered,
						"ml_rule_triggered", true,
						"final_rule_triggered", ruleTriggered,
						"probability", probability,
						"probability_percent", fmt.Sprintf("%.2f%%", probability*100),
						definitions.LogKeyGUID, m.guid,
					)

					level.Info(log.Logger).Log(
						definitions.LogKeyGUID, m.guid,
						definitions.LogKeyBruteForce, message,
						definitions.LogKeyUsername, m.username,
						definitions.LogKeyClientIP, m.clientIP,
						"probability", probability,
					)

					// Record this detection for future ML training
					_ = RecordLoginResult(m.ctx, false, features, m.clientIP, m.username, m.guid)
				} else {
					// Log the state after ML prediction when no brute force is detected
					util.DebugModule(definitions.DbgNeural,
						"action", "process_post_ml_prediction",
						"static_rule_triggered", false, // It was false before ML prediction
						"already_triggered", alreadyTriggered,
						"ml_rule_triggered", false,
						"final_rule_triggered", ruleTriggered,
						"probability", probability,
						"probability_percent", fmt.Sprintf("%.2f%%", probability*100),
						definitions.LogKeyGUID, m.guid,
					)
				}
			}
		}
	}

	// Use the standard processing with potentially updated ruleTriggered flag
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
	// Don't record login attempts in NoAuth mode
	if m.noAuth {
		util.DebugModule(definitions.DbgNeural,
			"action", "skip_record_login_feature",
			"reason", "no_auth_mode",
			"guid", m.guid,
			"client_ip", m.clientIP,
			"username", m.username,
		)
		return
	}

	// Record the login attempt for future ML training
	if m.mlDetector != nil {
		features, err := m.mlDetector.CollectFeatures()
		if err == nil {
			// This is a triggered feature, so it's a failed login
			_ = RecordLoginResult(m.ctx, false, features, m.clientIP, m.username, m.guid)
		}
	}
}

// RecordSuccessfulLogin records a successful login for ML training
func (m *MLBucketManager) RecordSuccessfulLogin() {
	// Don't record login attempts in NoAuth mode
	if m.noAuth {
		util.DebugModule(definitions.DbgNeural,
			"action", "skip_record_successful_login",
			"reason", "no_auth_mode",
			"guid", m.guid,
			"client_ip", m.clientIP,
			"username", m.username,
		)
		return
	}

	// Record the login attempt for future ML training
	if m.mlDetector != nil {
		// Ensure additional features are set on the detector before collecting features
		if m.additionalFeatures != nil {
			m.mlDetector.SetAdditionalFeatures(m.additionalFeatures)
		}

		features, err := m.mlDetector.CollectFeatures()
		if err == nil {
			// This is a successful login
			// Debug log to help diagnose the issue
			util.DebugModule(definitions.DbgNeural,
				"action", "record_successful_login",
				"guid", m.guid,
				"client_ip", m.clientIP,
				"username", m.username,
				"additional_features", fmt.Sprintf("%+v", features.AdditionalFeatures),
			)

			_ = RecordLoginResult(m.ctx, true, features, m.clientIP, m.username, m.guid)
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
