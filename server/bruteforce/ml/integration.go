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
	mlDetected         bool
	staticDetected     bool

	// Used for logging purposes
	mlProbability float64

	// Weights for decision-making
	staticWeight float64
	mlWeight     float64
}

// NewMLBucketManager creates a new bucket manager with ML capabilities
// If experimental_ml is not enabled, it returns a standard bucket manager instead
func NewMLBucketManager(ctx context.Context, guid, clientIP string) bruteforce.BucketManager {
	// Create the standard bucket manager
	standardBM := bruteforce.NewBucketManager(ctx, guid, clientIP)

	// Check if experimental ML is enabled
	if !config.GetEnvironment().GetExperimentalML() {
		// If ML is not enabled, return the standard bucket manager
		return standardBM
	}

	// Get weights and threshold from configuration, handling nil case
	staticWeight := 0.4 // Default static weight
	mlWeight := 0.6     // Default ML weight
	threshold := 0.7    // Default threshold

	nnConfig := config.GetFile().GetBruteForce().GetNeuralNetwork()
	if nnConfig != nil {
		staticWeight = nnConfig.GetStaticWeight()
		mlWeight = nnConfig.GetMLWeight()
		threshold = nnConfig.GetThreshold()
	}

	// Create our ML-enhanced bucket manager
	mlBM := &MLBucketManager{
		BucketManager: standardBM,
		ctx:           ctx,
		guid:          guid,
		clientIP:      clientIP,
		threshold:     threshold,
		noAuth:        false, // Default to false, will be set by the caller if needed
		staticWeight:  staticWeight,
		mlWeight:      mlWeight,
	}

	return mlBM
}

// WithUsername sets the username and initializes the ML detector
func (m *MLBucketManager) WithUsername(username string) bruteforce.BucketManager {
	m.username = username
	m.BucketManager = m.BucketManager.WithUsername(username)

	return m
}

// WithPassword sets the password for the bucket manager
func (m *MLBucketManager) WithPassword(password string) bruteforce.BucketManager {
	m.password = password
	m.BucketManager = m.BucketManager.WithPassword(password)

	return m
}

// WithAccountName sets the account name for the bucket manager and returns the updated bucket manager instance.
func (m *MLBucketManager) WithAccountName(accountName string) bruteforce.BucketManager {
	m.BucketManager = m.BucketManager.WithAccountName(accountName)

	return m
}

// WithProtocol sets the protocol for the bucket manager and returns the modified BucketManager instance.
func (m *MLBucketManager) WithProtocol(protocol string) bruteforce.BucketManager {
	m.BucketManager = m.BucketManager.WithProtocol(protocol)

	return m
}

// WithOIDCCID sets the OIDC Client ID for the bucket manager and returns the modified BucketManager instance.
func (m *MLBucketManager) WithOIDCCID(oidcCID string) bruteforce.BucketManager {
	m.BucketManager = m.BucketManager.WithOIDCCID(oidcCID)

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
	withError, staticRuleTriggered, ruleNumber := m.BucketManager.CheckBucketOverLimit(rules, network, message)

	// Store the original message from static rules
	staticMessage := ""
	if message != nil {
		staticMessage = *message
	}

	// Initialize ML detector if needed
	if m.mlDetector == nil && m.username != "" && m.clientIP != "" {
		// Use the singleton pattern to get the detector
		m.mlDetector = GetBruteForceMLDetector(m.ctx, m.guid, m.clientIP, m.username)

		// If we have additional features, set them on the detector
		if m.additionalFeatures != nil {
			m.mlDetector.SetAdditionalFeatures(m.additionalFeatures)
		}

		// Log that we had to initialize the detector
		util.DebugModule(definitions.DbgNeural,
			definitions.LogKeyGUID, m.guid,
			"action", "initialize_ml_detector_for_bucket_check",
			"client_ip", m.clientIP,
			"username", m.username,
			"has_additional_features", m.additionalFeatures != nil,
		)
	}

	// Only proceed with ML if experimental_ml is enabled and we have a detector
	if !withError && m.mlDetector != nil && config.GetEnvironment().GetExperimentalML() {
		// Check if the model is in learning mode
		isLearningMode := m.mlDetector.IsLearningMode() || config.GetFile().GetBruteForce().GetNeuralNetwork().GetDryRun()

		// Log the state of static bucket system before ML prediction
		util.DebugModule(definitions.DbgNeural,
			definitions.LogKeyGUID, m.guid,
			"action", "pre_ml_prediction",
			"static_rule_triggered", staticRuleTriggered,
			"static_error", withError,
			"learning_mode", isLearningMode,
		)

		// If the model is in learning mode, use only static rules
		if isLearningMode {
			ruleTriggered = staticRuleTriggered

			util.DebugModule(definitions.DbgNeural,
				definitions.LogKeyGUID, m.guid,
				"action", "learning_mode_static_only",
				"static_rule_triggered", staticRuleTriggered,
				"final_rule_triggered", ruleTriggered,
			)

			if ruleTriggered && message != nil {
				*message = "Static brute force detection triggered (neural network in learning mode)"
			}

			_, probability, err := m.mlDetector.Predict()
			m.mlProbability = probability

			if err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyGUID, m.guid,
					definitions.LogKeyMsg, fmt.Sprintf("ML prediction error: %v", err),
				)
			}

			return withError, ruleTriggered, ruleNumber
		}

		isBruteForce, probability, err := m.mlDetector.Predict()
		m.mlProbability = probability

		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, m.guid,
				definitions.LogKeyMsg, fmt.Sprintf("ML prediction error: %v", err),
			)

			// If ML fails, fall back to static rule result
			return false, staticRuleTriggered, ruleNumber
		}

		// Calculate weighted decision
		// Convert boolean values to numeric scores
		staticScore := 0.0
		if staticRuleTriggered {
			staticScore = 1.0
			m.staticDetected = true
		}

		mlScore := probability // ML already gives us a probability

		// Calculate weighted score
		weightedScore := (staticScore * m.staticWeight) + (mlScore * m.mlWeight)

		// Log the weighted decision calculation
		util.DebugModule(definitions.DbgNeural,
			definitions.LogKeyGUID, m.guid,
			"action", "weighted_decision_calculation",
			"static_score", staticScore,
			"static_weight", m.staticWeight,
			"ml_score", mlScore,
			"ml_weight", m.mlWeight,
			"weighted_score", weightedScore,
			"threshold", m.threshold,
		)

		// Determine if this should trigger based on the weighted score
		// If the weighted score is above the threshold, trigger
		if weightedScore >= m.threshold {
			ruleTriggered = true
			if message != nil {
				*message = fmt.Sprintf("Weighted brute force detection triggered (score: %.2f, threshold: %.2f)",
					weightedScore, m.threshold)
			}

			util.DebugModule(definitions.DbgNeural,
				definitions.LogKeyGUID, m.guid,
				"action", "post_weighted_decision",
				"static_rule_triggered", staticRuleTriggered,
				"ml_rule_triggered", isBruteForce,
				"weighted_score", weightedScore,
				"threshold", m.threshold,
				"final_rule_triggered", ruleTriggered,
			)

			level.Info(log.Logger).Log(
				definitions.LogKeyGUID, m.guid,
				definitions.LogKeyBruteForce, func() string {
					if message != nil {
						return *message
					}

					return "Weighted brute force detection triggered"
				}(),
				definitions.LogKeyUsername, m.username,
				definitions.LogKeyClientIP, m.clientIP,
				"static_triggered", staticRuleTriggered,
				"ml_probability", probability,
				"weighted_score", weightedScore,
			)
		} else {
			// Weighted score is below threshold, don't trigger
			ruleTriggered = false

			// If static rules triggered but weighted decision says no, log this override
			if staticRuleTriggered {
				if message != nil {
					*message = fmt.Sprintf("Weighted decision overrode static brute force detection (score: %.2f, threshold: %.2f)",
						weightedScore, m.threshold)
				}

				util.DebugModule(definitions.DbgNeural,
					definitions.LogKeyGUID, m.guid,
					"action", "post_weighted_decision",
					"static_rule_triggered", staticRuleTriggered,
					"ml_rule_triggered", isBruteForce,
					"weighted_score", weightedScore,
					"threshold", m.threshold,
					"final_rule_triggered", ruleTriggered,
					"static_message", staticMessage,
				)

				level.Info(log.Logger).Log(
					definitions.LogKeyGUID, m.guid,
					definitions.LogKeyBruteForce, func() string {
						if message != nil {
							return *message
						}

						return "Weighted decision overrode static brute force detection"
					}(),
					definitions.LogKeyUsername, m.username,
					definitions.LogKeyClientIP, m.clientIP,
					"static_triggered", staticRuleTriggered,
					"ml_probability", probability,
					"weighted_score", weightedScore,
					"static_message", staticMessage,
				)
			} else {
				// Neither static rules nor weighted decision triggered
				util.DebugModule(definitions.DbgNeural,
					definitions.LogKeyGUID, m.guid,
					"action", "post_weighted_decision",
					"static_rule_triggered", staticRuleTriggered,
					"ml_rule_triggered", isBruteForce,
					"weighted_score", weightedScore,
					"threshold", m.threshold,
					"final_rule_triggered", ruleTriggered,
				)
			}
		}
	} else {
		// If ML is not enabled or detector is not available, use static rule result
		ruleTriggered = staticRuleTriggered
	}

	return withError, ruleTriggered, ruleNumber
}

// Close cleans up resources when the MLBucketManager is no longer needed
// This is a no-op since we're using a global ML system
func (m *MLBucketManager) Close() {
	// No-op - the ML system is managed globally and will be cleaned up by ShutdownMLSystem
}

// TrainModel manually triggers training of the ML model
// Returns an error if experimental_ml is not enabled
func (m *MLBucketManager) TrainModel(maxSamples, epochs int) error {
	// Check if experimental ML is enabled
	if !config.GetEnvironment().GetExperimentalML() {
		return fmt.Errorf("cannot train model: experimental_ml is not enabled")
	}

	// Ensure the ML system is initialized
	if mlSystem.GetTrainer() == nil {
		if err := InitMLSystem(m.ctx); err != nil {
			return fmt.Errorf("failed to initialize ML system: %w", err)
		}
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyGUID, m.guid,
		definitions.LogKeyMsg, fmt.Sprintf("Manually triggering ML model training with %d samples for %d epochs", maxSamples, epochs),
	)

	// Get the trainer
	trainer := mlSystem.GetTrainer()
	if trainer == nil {
		return fmt.Errorf("cannot train model: trainer is nil after initialization")
	}

	// Train the model
	err := trainer.TrainWithStoredData(maxSamples, epochs)
	if err != nil {
		return err
	}

	// Save the trained model to Redis
	return trainer.SaveModelToRedis()
}

// RecordLoginFeature records a login feature for ML training
func (m *MLBucketManager) RecordLoginFeature() {
	// Don't record login attempts in NoAuth mode
	if m.noAuth {
		util.DebugModule(definitions.DbgNeural,
			definitions.LogKeyGUID, m.guid,
			"action", "skip_record_login_feature",
			"reason", "no_auth_mode",
			"client_ip", m.clientIP,
			"username", m.username,
		)

		return
	}

	// Don't record login attempts if experimental_ml is not enabled
	if !config.GetEnvironment().GetExperimentalML() {
		util.DebugModule(definitions.DbgNeural,
			definitions.LogKeyGUID, m.guid,
			"action", "skip_record_login_feature",
			"reason", "experimental_ml_not_enabled",
			"client_ip", m.clientIP,
			"username", m.username,
		)

		return
	}

	// Initialize ML detector if needed
	if m.mlDetector == nil && m.username != "" && m.clientIP != "" {
		// Use the singleton pattern to get the detector
		m.mlDetector = GetBruteForceMLDetector(m.ctx, m.guid, m.clientIP, m.username)

		// Log that we had to initialize the detector
		util.DebugModule(definitions.DbgNeural,
			definitions.LogKeyGUID, m.guid,
			"action", "initialize_ml_detector_for_login_feature",
			"client_ip", m.clientIP,
			"username", m.username,
		)
	}

	// Record the login attempt for future ML training
	if m.mlDetector != nil {
		// Ensure additional features are set on the detector before collecting features
		if m.additionalFeatures != nil {
			m.mlDetector.SetAdditionalFeatures(m.additionalFeatures)
		}

		features, err := m.mlDetector.CollectFeatures()
		if err == nil {
			// This is a triggered feature, so it's a failed login
			_ = RecordLoginResult(m.ctx, false, features, m.clientIP, m.username, m.guid)
		}
	} else {
		util.DebugModule(definitions.DbgNeural,
			definitions.LogKeyGUID, m.guid,
			"action", "skip_record_login_feature",
			"reason", "ml_detector_not_initialized",
			"client_ip", m.clientIP,
			"username", m.username,
		)
	}
}

// RecordSuccessfulLogin records a successful login for ML training
func (m *MLBucketManager) RecordSuccessfulLogin() {
	// Don't record login attempts in NoAuth mode
	if m.noAuth {
		util.DebugModule(definitions.DbgNeural,
			definitions.LogKeyGUID, m.guid,
			"action", "skip_record_successful_login",
			"reason", "no_auth_mode",
			"client_ip", m.clientIP,
			"username", m.username,
		)

		return
	}

	// Don't record login attempts if experimental_ml is not enabled
	if !config.GetEnvironment().GetExperimentalML() {
		util.DebugModule(definitions.DbgNeural,
			definitions.LogKeyGUID, m.guid,
			"action", "skip_record_successful_login",
			"reason", "experimental_ml_not_enabled",
			"client_ip", m.clientIP,
			"username", m.username,
		)

		return
	}

	// Initialize ML detector if needed
	if m.mlDetector == nil && m.username != "" && m.clientIP != "" {
		// Use the singleton pattern to get the detector
		m.mlDetector = GetBruteForceMLDetector(m.ctx, m.guid, m.clientIP, m.username)

		// Log that we had to initialize the detector
		util.DebugModule(definitions.DbgNeural,
			definitions.LogKeyGUID, m.guid,
			"action", "initialize_ml_detector_for_successful_login",
			"client_ip", m.clientIP,
			"username", m.username,
		)
	}

	// Record the login attempt for future ML training
	if m.mlDetector != nil {
		// Ensure additional features are set on the detector before collecting features
		if m.additionalFeatures != nil {
			m.mlDetector.SetAdditionalFeatures(m.additionalFeatures)
		} else {
			util.DebugModule(definitions.DbgNeural,
				definitions.LogKeyGUID, m.guid,
				"action", "record_successful_login",
				"warning", "no_additional_features",
				"client_ip", m.clientIP,
				"username", m.username,
			)
		}

		features, err := m.mlDetector.CollectFeatures()
		if err == nil {
			// This is a successful login
			// Debug log to help diagnose the issue
			util.DebugModule(definitions.DbgNeural,
				definitions.LogKeyGUID, m.guid,
				"action", "record_successful_login",
				"client_ip", m.clientIP,
				"username", m.username,
				"additional_features", fmt.Sprintf("%+v", features.AdditionalFeatures),
			)

			_ = RecordLoginResult(m.ctx, true, features, m.clientIP, m.username, m.guid)
		} else {
			util.DebugModule(definitions.DbgNeural,
				definitions.LogKeyGUID, m.guid,
				"action", "record_successful_login_error",
				"error", err.Error(),
				"client_ip", m.clientIP,
				"username", m.username,
			)
		}
	} else {
		util.DebugModule(definitions.DbgNeural,
			definitions.LogKeyGUID, m.guid,
			"action", "skip_record_successful_login",
			"reason", "ml_detector_not_initialized",
			"client_ip", m.clientIP,
			"username", m.username,
		)
	}
}

// GetBruteForceName returns the name of the brute force detection mechanism.
// There are three possible scenarios:
// 1. Only the static bucket system triggered - use the bucket name that triggered the system
// 2. Only the neural network triggered - use "neural_network" as the bucket name
// 3. Both systems triggered - use a combination of the bucket name and "neural_network"
func (m *MLBucketManager) GetBruteForceName() string {
	// Case 1: Only static bucket system triggered
	if m.staticDetected && !m.mlDetected {
		return m.BucketManager.GetBruteForceName()
	}

	// Case 2: Only neural network triggered
	if m.mlDetected && !m.staticDetected {
		return "neural_network"
	}

	// Case 3: Both systems triggered
	if m.mlDetected && m.staticDetected {
		bucketName := m.BucketManager.GetBruteForceName()
		if bucketName != "" {
			return bucketName + ",neural_network"
		}
	}

	// Default fallback (should not happen if flags are set correctly)
	return m.BucketManager.GetBruteForceName()
}

// GetMLProbability returns the probability value from the ML prediction.
// If ML prediction has not been done or ML is not activated, it returns 0.0.
func (m *MLBucketManager) GetMLProbability() float64 {
	return m.mlProbability
}
