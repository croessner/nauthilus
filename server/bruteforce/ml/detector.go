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
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/go-kit/log/level"
	"github.com/redis/go-redis/v9"
)

// BruteForceMLDetector implements machine learning based brute force detection
type BruteForceMLDetector struct {
	ctx                  context.Context
	guid                 string
	clientIP             string
	username             string
	model                *NeuralNetwork
	additionalFeatures   map[string]any
	featureEncodingTypes map[string]string
}

// Predict determines if the current login attempt is part of a brute force attack
func (d *BruteForceMLDetector) Predict() (bool, float64, error) {
	// Start timing the prediction
	startTime := time.Now()

	util.DebugModule(definitions.DbgNeural,
		"action", "predict_start",
		definitions.LogKeyGUID, d.guid,
		definitions.LogKeyClientIP, d.clientIP,
		definitions.LogKeyUsername, d.username,
	)

	// Collect features for prediction

	features, err := d.CollectFeatures()
	if err != nil {
		return false, 0, err
	}

	// Start with standard features
	inputs := []float64{
		features.TimeBetweenAttempts,
		features.FailedAttemptsLastHour,
		features.DifferentUsernames,
		features.DifferentPasswords,
		features.TimeOfDay,
		features.SuspiciousNetwork,
	}

	// Add additional features if they exist
	if features.AdditionalFeatures != nil && len(features.AdditionalFeatures) > 0 {
		util.DebugModule(definitions.DbgNeural,
			"action", "predict_additional_features",
			"additional_features_count", len(features.AdditionalFeatures),
			definitions.LogKeyGUID, d.guid,
		)

		// Sort keys for consistent order
		keys := make([]string, 0, len(features.AdditionalFeatures))
		for k := range features.AdditionalFeatures {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Add each additional feature to the inputs
		for _, key := range keys {
			value := features.AdditionalFeatures[key]

			// Process the value based on its type
			switch v := value.(type) {
			case float64:
				inputs = append(inputs, v)
			case float32:
				inputs = append(inputs, float64(v))
			case int:
				inputs = append(inputs, float64(v))
			case int64:
				inputs = append(inputs, float64(v))
			case bool:
				if v {
					inputs = append(inputs, 1.0)
				} else {
					inputs = append(inputs, 0.0)
				}
			case string:
				// Get the global trainer to access encodings
				globalTrainerMutex.RLock()
				trainer := globalTrainer
				globalTrainerMutex.RUnlock()

				if trainer != nil {
					// Check the encoding type for this feature
					encodingType := trainer.GetFeatureEncodingType(key)

					if encodingType == EmbeddingEncoding {
						// Use embedding encoding for this feature
						embedding := trainer.generateEmbedding(v)
						inputs = append(inputs, embedding...)

						util.DebugModule(definitions.DbgNeural,
							"action", "predict_embedding",
							"key", key,
							"value", v,
							"embedding_size", len(embedding),
							definitions.LogKeyGUID, d.guid,
						)
					} else {
						// Use one-hot encoding for this feature (default)
						if trainer.oneHotEncodings != nil {
							// Check if we've seen this feature before
							if featureEncodings, exists := trainer.oneHotEncodings[key]; exists {
								// Check if we've seen this value before
								if index, exists := featureEncodings[v]; exists {
									// Add one-hot encoded values to the feature vector
									for j := 0; j < trainer.oneHotSizes[key]; j++ {
										if j == index {
											inputs = append(inputs, 1.0)
										} else {
											inputs = append(inputs, 0.0)
										}
									}

									util.DebugModule(definitions.DbgNeural,
										"action", "predict_one_hot_encoding",
										"key", key,
										"value", v,
										"one_hot_values", trainer.oneHotSizes[key],
										"one_hot_index", index,
										definitions.LogKeyGUID, d.guid,
									)
								} else {
									// Value not seen during training, use a default value
									// Add zeros for all possible values of this feature
									for j := 0; j < trainer.oneHotSizes[key]; j++ {
										inputs = append(inputs, 0.0)
									}

									util.DebugModule(definitions.DbgNeural,
										"action", "predict_one_hot_encoding_unknown_value",
										"key", key,
										"value", v,
										"one_hot_values", trainer.oneHotSizes[key],
										definitions.LogKeyGUID, d.guid,
									)
								}
							} else {
								// Feature not seen during training, use a default value
								inputs = append(inputs, 0.5)

								util.DebugModule(definitions.DbgNeural,
									"action", "predict_unknown_categorical_feature",
									"key", key,
									"value", v,
									definitions.LogKeyGUID, d.guid,
								)
							}
						} else {
							// Fallback to old method if one-hot encoding is not available
							hash := util.GetHash(v)
							if len(hash) > 8 {
								hash = hash[:8]
							}

							if hashInt, err := strconv.ParseInt(hash, 16, 64); err == nil {
								inputs = append(inputs, float64(hashInt%1000)/1000.0)
							} else {
								inputs = append(inputs, 0.5)
							}

							util.DebugModule(definitions.DbgNeural,
								"action", "predict_fallback_hash",
								"key", key,
								"value", v,
								definitions.LogKeyGUID, d.guid,
							)
						}
					}
				} else {
					// Fallback to old method if trainer is not available
					hash := util.GetHash(v)
					if len(hash) > 8 {
						hash = hash[:8]
					}

					if hashInt, err := strconv.ParseInt(hash, 16, 64); err == nil {
						inputs = append(inputs, float64(hashInt%1000)/1000.0)
					} else {
						inputs = append(inputs, 0.5)
					}

					util.DebugModule(definitions.DbgNeural,
						"action", "predict_fallback_hash",
						"key", key,
						"value", v,
						definitions.LogKeyGUID, d.guid,
					)
				}
			default:
				// For other types, use a default value
				inputs = append(inputs, 0.5)
			}

			util.DebugModule(definitions.DbgNeural,
				"action", "predict_additional_feature",
				"key", key,
				"value", value,
				definitions.LogKeyGUID, d.guid,
			)
		}
	}

	// Create human-readable descriptions for the input values
	inputDescriptions := []string{
		fmt.Sprintf("TimeBetweenAttempts: %.2f seconds", features.TimeBetweenAttempts),
		fmt.Sprintf("FailedAttemptsLastHour: %.0f", features.FailedAttemptsLastHour),
		fmt.Sprintf("DifferentUsernames: %.0f", features.DifferentUsernames),
		fmt.Sprintf("DifferentPasswords: %.0f", features.DifferentPasswords),
		fmt.Sprintf("TimeOfDay: %.2f (hour: %.0f)", features.TimeOfDay, features.TimeOfDay*24),
		fmt.Sprintf("SuspiciousNetwork: %v", features.SuspiciousNetwork > 0.5),
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "predict_inputs_prepared",
		"inputs", fmt.Sprintf("%v", inputs),
		"input_count", len(inputs),
		"input_descriptions", strings.Join(inputDescriptions, ", "),
		definitions.LogKeyGUID, d.guid,
	)

	// Record feature values as metrics
	metrics := GetMLMetrics()
	metrics.RecordFeatureValue("time_between_attempts", features.TimeBetweenAttempts)
	metrics.RecordFeatureValue("failed_attempts_last_hour", features.FailedAttemptsLastHour)
	metrics.RecordFeatureValue("different_usernames", features.DifferentUsernames)
	metrics.RecordFeatureValue("different_passwords", features.DifferentPasswords)
	metrics.RecordFeatureValue("time_of_day", features.TimeOfDay)
	metrics.RecordFeatureValue("suspicious_network", features.SuspiciousNetwork)

	// Record additional features
	if features.AdditionalFeatures != nil {
		for key, value := range features.AdditionalFeatures {
			// Convert the value to float64
			var floatValue float64
			switch v := value.(type) {
			case float64:
				floatValue = v
			case float32:
				floatValue = float64(v)
			case int:
				floatValue = float64(v)
			case int64:
				floatValue = float64(v)
			case bool:
				if v {
					floatValue = 1.0
				} else {
					floatValue = 0.0
				}
			case string:
				// Try to convert string to float
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					floatValue = f
				} else {
					// If string can't be converted to float, use a hash of the string
					// normalized to [0,1]
					hash := util.GetHash(v)
					// Use the first 8 characters of the hash as a hex number
					if len(hash) > 8 {
						hash = hash[:8]
					}

					// Convert hex to int
					if hashInt, err := strconv.ParseInt(hash, 16, 64); err == nil {
						// Normalize to [0,1]
						floatValue = float64(hashInt%1000) / 1000.0
					} else {
						// Fallback
						floatValue = 0.5
					}
				}
			default:
				// For other types, use a default value
				floatValue = 0.5
			}

			metrics.RecordFeatureValue("additional_"+key, floatValue)
		}
	}

	// Normalize inputs
	normalizedInputs := normalizeInputs(inputs)

	// Create human-readable descriptions for the normalized input values
	normalizedDescriptions := []string{
		fmt.Sprintf("TimeBetweenAttempts: %.2f", normalizedInputs[0]),
		fmt.Sprintf("FailedAttemptsLastHour: %.2f", normalizedInputs[1]),
		fmt.Sprintf("DifferentUsernames: %.2f", normalizedInputs[2]),
		fmt.Sprintf("DifferentPasswords: %.2f", normalizedInputs[3]),
		fmt.Sprintf("TimeOfDay: %.2f", normalizedInputs[4]),
		fmt.Sprintf("SuspiciousNetwork: %.2f", normalizedInputs[5]),
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "predict_inputs_normalized",
		"normalized_inputs", fmt.Sprintf("%v", normalizedInputs),
		"normalized_descriptions", strings.Join(normalizedDescriptions, ", "),
		definitions.LogKeyGUID, d.guid,
	)

	// Make prediction
	outputs := d.model.FeedForward(normalizedInputs)

	// The output is the probability of a brute force attack
	probability := outputs[0]

	// Human-readable probability description
	probabilityDesc := fmt.Sprintf("%.2f%%", probability*100)

	util.DebugModule(definitions.DbgNeural,
		"action", "predict_probability_calculated",
		"probability", probability,
		"probability_percent", probabilityDesc,
		definitions.LogKeyGUID, d.guid,
	)

	// Check if the model has been trained with real data
	modelTrainedMutex.RLock()
	isModelTrained := modelTrained
	modelTrainedMutex.RUnlock()

	// Get threshold from configuration, handling nil case
	threshold := 0.7 // Default threshold
	nnConfig := config.GetFile().GetBruteForce().GetNeuralNetwork()
	if nnConfig != nil {
		threshold = nnConfig.GetThreshold()
	}

	isBruteForce := probability > threshold

	// If the model hasn't been trained yet, we're in learning mode
	// We still collect data but don't make decisions based on ML predictions
	if !isModelTrained {
		// In learning mode, we don't consider it a brute force attack
		isBruteForce = false

		util.DebugModule(definitions.DbgNeural,
			"action", "predict_learning_mode",
			"reason", "model_not_trained_yet",
			"probability", probability,
			"probability_percent", fmt.Sprintf("%.2f%%", probability*100),
			"threshold", threshold,
			"threshold_percent", fmt.Sprintf("%.2f%%", threshold*100),
			definitions.LogKeyGUID, d.guid,
		)
	}

	// Human-readable threshold and decision description
	thresholdDesc := fmt.Sprintf("%.2f%%", threshold*100)
	decisionDesc := "No brute force attack detected"
	if isBruteForce {
		decisionDesc = "Brute force attack detected"
	} else if !isModelTrained {
		decisionDesc = "Learning mode - collecting data"
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "predict_complete",
		"is_brute_force", isBruteForce,
		"decision", decisionDesc,
		"probability", probability,
		"probability_percent", fmt.Sprintf("%.2f%%", probability*100),
		"threshold", threshold,
		"threshold_percent", thresholdDesc,
		"model_trained", isModelTrained,
		definitions.LogKeyGUID, d.guid,
	)

	// Calculate prediction duration
	duration := time.Since(startTime).Seconds()

	// Record prediction metrics
	metrics.RecordPrediction(probability, isBruteForce, duration)

	return isBruteForce, probability, nil
}

// GetBruteForceMLDetector creates a new detector instance for a specific request
// Returns nil if experimental_ml is not enabled
func GetBruteForceMLDetector(ctx context.Context, guid, clientIP, username string) *BruteForceMLDetector {
	// Check if experimental ML is enabled
	if !config.GetEnvironment().GetExperimentalML() {
		util.DebugModule(definitions.DbgNeural,
			"action", "get_detector_skipped",
			"reason", "experimental_ml_not_enabled",
			definitions.LogKeyGUID, guid,
		)

		return nil
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "get_detector_start",
		definitions.LogKeyGUID, guid,
		definitions.LogKeyClientIP, clientIP,
		definitions.LogKeyUsername, username,
	)

	// Acquire read lock to check if globalTrainer is nil
	globalTrainerMutex.RLock()
	trainerIsNil := globalTrainer == nil
	globalTrainerMutex.RUnlock()

	// Ensure the ML system is initialized
	if trainerIsNil {
		util.DebugModule(definitions.DbgNeural,
			"action", "get_detector_init_system",
			"reason", "global_trainer_nil",
			definitions.LogKeyGUID, guid,
		)

		if err := InitMLSystem(ctx); err != nil {
			util.DebugModule(definitions.DbgNeural,
				"action", "get_detector_init_system_error",
				"error", err.Error(),
				definitions.LogKeyGUID, guid,
			)

			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, fmt.Sprintf("Failed to initialize ML system: %v", err),
			)
		}
	}

	// Acquire read lock to check if globalTrainer is still nil after initialization
	globalTrainerMutex.RLock()
	trainerIsStillNil := globalTrainer == nil
	globalTrainerMutex.RUnlock()

	// If globalTrainer is still nil after initialization, create a default model
	var model *NeuralNetwork
	if trainerIsStillNil {
		util.DebugModule(definitions.DbgNeural,
			"action", "get_detector_create_default_model",
			"reason", "global_trainer_still_nil_after_init",
			definitions.LogKeyGUID, guid,
		)

		// Default input size is 6 for the standard features
		inputSize := 6

		// Skip dynamic neuron adjustment during tests
		if os.Getenv("NAUTHILUS_TESTING") != "1" {
			// First, try to get the canonical list of features from Redis
			canonicalFeatures, err := GetDynamicFeaturesFromRedis(ctx)
			if err == nil && len(canonicalFeatures) > 0 {
				// Add the number of canonical features to the input size
				inputSize += len(canonicalFeatures)

				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Creating default model with %d input neurons (%d standard + %d dynamic) based on canonical feature list",
						inputSize, 6, len(canonicalFeatures)),
					"features", strings.Join(canonicalFeatures, ", "),
					definitions.LogKeyGUID, guid,
				)

				util.DebugModule(definitions.DbgNeural,
					"action", "create_default_model_with_canonical_features",
					"canonical_features_count", len(canonicalFeatures),
					"total_input_size", inputSize,
					definitions.LogKeyGUID, guid,
				)
			} else {
				// If we couldn't get the canonical list, fall back to checking context
				// Check if we have additional features from Lua context
				if additionalFeatures, ok := ctx.Value(definitions.CtxAdditionalFeaturesKey).(map[string]any); ok && len(additionalFeatures) > 0 {
					// Add the number of additional features to the input size
					inputSize += len(additionalFeatures)

					// Store these features in the canonical list for future use
					var featureNames []string
					for featureName := range additionalFeatures {
						featureNames = append(featureNames, featureName)
					}

					if storeErr := StoreDynamicFeaturesToRedis(ctx, featureNames); storeErr != nil {
						level.Warn(log.Logger).Log(
							definitions.LogKeyMsg, fmt.Sprintf("Failed to store context features to canonical list: %v", storeErr),
							definitions.LogKeyGUID, guid,
						)
					}

					util.DebugModule(definitions.DbgNeural,
						"action", "adjust_default_model_input_size",
						"additional_features_count", len(additionalFeatures),
						"total_input_size", inputSize,
						definitions.LogKeyGUID, guid,
					)

					level.Info(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Creating default model with %d input neurons to account for dynamic neurons", inputSize),
						definitions.LogKeyGUID, guid,
					)
				}
			}
		} else {
			util.DebugModule(definitions.DbgNeural,
				"action", "skip_dynamic_neuron_adjustment_for_default_model",
				"reason", "running_in_test_environment",
				"input_size", inputSize,
				definitions.LogKeyGUID, guid,
			)
		}

		// Create a default model with the adjusted input size
		model = NewNeuralNetwork(inputSize, 1)

		// Ensure metrics are updated with the correct input size
		GetMLMetrics().RecordNetworkStructure(inputSize, model.hiddenSize, 1)
	} else {
		// Get the model from the global trainer
		globalTrainerMutex.RLock()
		model = globalTrainer.GetModel()
		globalTrainerMutex.RUnlock()

		// Check if the model's input size matches the expected size based on canonical features
		if model != nil && os.Getenv("NAUTHILUS_TESTING") != "1" {
			// Get the canonical list of features from Redis
			canonicalFeatures, err := GetDynamicFeaturesFromRedis(ctx)
			if err == nil && len(canonicalFeatures) > 0 {
				// Calculate expected input size: 6 standard features + canonical features
				expectedInputSize := 6 + len(canonicalFeatures)

				// If the model's input size is smaller than expected, we need to create a new model
				if model.inputSize < expectedInputSize {
					level.Info(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Model input size (%d) is smaller than expected (%d) based on canonical features. Creating new model.",
							model.inputSize, expectedInputSize),
						"canonical_features_count", len(canonicalFeatures),
						definitions.LogKeyGUID, guid,
					)

					// Create a new model with the correct input size
					model = NewNeuralNetwork(expectedInputSize, 1)

					// Ensure metrics are updated with the correct input size
					GetMLMetrics().RecordNetworkStructure(expectedInputSize, model.hiddenSize, 1)

					// Update the global trainer with the new model
					globalTrainerMutex.Lock()
					globalTrainer.model = model
					globalTrainerMutex.Unlock()

					// Save the new model to Redis and notify other instances
					go func() {
						// Create a new context with a timeout for the save operation
						saveCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						defer cancel()

						if err := globalTrainer.SaveModelToRedis(); err != nil {
							level.Error(log.Logger).Log(
								definitions.LogKeyMsg, fmt.Sprintf("Failed to save new model to Redis: %v", err),
								definitions.LogKeyGUID, guid,
							)
						} else {
							level.Info(log.Logger).Log(
								definitions.LogKeyMsg, "Successfully saved new model to Redis",
								definitions.LogKeyGUID, guid,
							)

							// Publish an update notification to other instances
							if err := PublishModelUpdate(saveCtx); err != nil {
								level.Error(log.Logger).Log(
									definitions.LogKeyMsg, fmt.Sprintf("Failed to publish model update notification: %v", err),
									definitions.LogKeyGUID, guid,
								)
							} else {
								level.Info(log.Logger).Log(
									definitions.LogKeyMsg, "Successfully published model update notification",
									definitions.LogKeyGUID, guid,
								)
							}
						}
					}()
				}
			}
		}
	}

	// Get the canonical list of features from Redis
	canonicalFeatures, err := GetDynamicFeaturesFromRedis(ctx)
	if err == nil && len(canonicalFeatures) > 0 {
		// Get existing additional features from context
		var existingFeatures map[string]any
		if exists, ok := ctx.Value(definitions.CtxAdditionalFeaturesKey).(map[string]any); ok {
			existingFeatures = exists
		} else {
			existingFeatures = make(map[string]any)
		}

		// Add any missing canonical features to the context
		featuresAdded := false
		var addedFeatures []string
		for _, feature := range canonicalFeatures {
			if _, exists := existingFeatures[feature]; !exists {
				existingFeatures[feature] = 0.0
				featuresAdded = true
				addedFeatures = append(addedFeatures, feature)
			}
		}

		// If we added features, update the context and log
		if featuresAdded {
			ctx = context.WithValue(ctx, definitions.CtxAdditionalFeaturesKey, existingFeatures)

			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Added %d missing features from canonical list to context", len(addedFeatures)),
				"features", strings.Join(addedFeatures, ", "),
				definitions.LogKeyGUID, guid,
			)

			util.DebugModule(definitions.DbgNeural,
				"action", "add_canonical_features_to_context",
				"features_added", len(addedFeatures),
				"features", strings.Join(addedFeatures, ", "),
				"total_features", len(existingFeatures),
				definitions.LogKeyGUID, guid,
			)
		}
	}

	// Get encoding type preferences from the context if they exist
	var encodingTypes map[string]string

	if exists, ok := ctx.Value(definitions.CtxFeatureEncodingTypeKey).(map[string]string); ok {
		encodingTypes = exists
	}

	// Create a new detector for this request
	detector := &BruteForceMLDetector{
		ctx:                  ctx,
		guid:                 guid,
		clientIP:             clientIP,
		username:             username,
		model:                model,                // Use the globally trained model
		additionalFeatures:   make(map[string]any), // Initialize empty additional features
		featureEncodingTypes: encodingTypes,
	}

	// Log detailed information about the model for diagnostic purposes
	if model != nil {
		// Count additional features from context
		additionalFeaturesCount := 0
		if additionalFeatures, ok := ctx.Value(definitions.CtxAdditionalFeaturesKey).(map[string]any); ok {
			additionalFeaturesCount = len(additionalFeatures)
		}

		// Log model information
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("ML detector using model with %d input neurons (%d standard + %d dynamic)",
				model.inputSize, 6, model.inputSize-6),
			"additional_features_in_context", additionalFeaturesCount,
		)
	}

	// Debug logging with model input size if available
	if detector.model != nil {
		util.DebugModule(definitions.DbgNeural,
			"action", "get_detector_complete",
			definitions.LogKeyGUID, guid,
			"model_nil", false,
			"model_input_size", detector.model.inputSize,
		)
	} else {
		util.DebugModule(definitions.DbgNeural,
			"action", "get_detector_complete",
			definitions.LogKeyGUID, guid,
			"model_nil", true,
		)
	}

	return detector
}

// ShouldIgnoreIP checks if an IP address should be ignored for ML training.
// It applies the same filtering logic as the CheckBruteForce function:
// - Checks if the IP is localhost or empty
// - Checks if the IP is in the soft whitelist
// - Checks if the IP is in the IP whitelist
func ShouldIgnoreIP(clientIP, username, guid string) bool {
	// Check if the IP is localhost or empty
	if clientIP == definitions.Localhost4 || clientIP == definitions.Localhost6 || clientIP == "" {
		util.DebugModule(
			definitions.DbgNeural,
			"action", "ignore_ip_for_ml_training",
			"reason", "localhost_or_empty",
			"client_ip", clientIP,
			definitions.LogKeyGUID, guid,
		)

		return true
	}

	// Check if the IP is in the soft whitelist
	if config.GetFile().GetBruteForce().HasSoftWhitelist() {
		if util.IsSoftWhitelisted(username, clientIP, guid, config.GetFile().GetBruteForce().GetSoftWhitelist()) {
			util.DebugModule(
				definitions.DbgNeural,
				"action", "ignore_ip_for_ml_training",
				"reason", "soft_whitelisted",
				"client_ip", clientIP,
				"username", username,
				definitions.LogKeyGUID, guid,
			)

			return true
		}
	}

	// Check if the IP is in the IP whitelist
	if len(config.GetFile().GetBruteForce().GetIPWhitelist()) > 0 {
		if util.IsInNetwork(config.GetFile().GetBruteForce().GetIPWhitelist(), guid, clientIP) {
			util.DebugModule(
				definitions.DbgNeural,
				"action", "ignore_ip_for_ml_training",
				"reason", "ip_whitelisted",
				"client_ip", clientIP,
				definitions.LogKeyGUID, guid,
			)

			return true
		}
	}

	return false
}

// RecordLoginResult records the result of a login attempt for future training.
// It checks the current balance of training data before recording to prevent imbalance.
//
// This function implements the 80:20 rule to ensure that neither successful nor failed
// login attempts dominate the training data. If adding a new sample would cause the
// ratio to exceed these bounds, the recording is skipped and an info message is logged.
//
// This prevents the model from becoming biased over time, which could happen if there
// is a sudden influx of only one type of login attempt (e.g., during an attack or
// during normal operation with very few failures).
//
// For recording feedback on predictions, use RecordFeedback instead.
func RecordLoginResult(ctx context.Context, success bool, features *LoginFeatures, clientIP string, username string, guid string) error {
	// Check if experimental ML is enabled
	if !config.GetEnvironment().GetExperimentalML() {
		util.DebugModule(definitions.DbgNeural,
			"action", "skip_record_login_result",
			"reason", "experimental_ml_not_enabled",
			definitions.LogKeyGUID, guid,
		)

		return nil
	}

	// Check if the IP should be ignored for ML training
	if ShouldIgnoreIP(clientIP, username, guid) {
		return nil
	}

	// Store the login attempt result and features for future model training
	data := TrainingData{
		Success:  success,
		Features: features,
		Time:     time.Now(),
	}

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:training:data"

	// Check current balance before recording
	// We'll sample a subset of the data to determine the current ratio
	sampleSize := 1000 // Sample size to check ratio

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	jsonData, err := rediscli.GetClient().GetReadHandle().LRange(ctx, key, 0, int64(sampleSize-1)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}

	// If we have enough data to check the ratio
	if len(jsonData) > 50 { // Only check if we have a meaningful sample size
		successCount := 0
		failCount := 0

		// Count successful and failed samples
		for _, item := range jsonData {
			var sample TrainingData
			if err := json.Unmarshal([]byte(item), &sample); err != nil {
				continue // Skip invalid entries
			}

			if sample.Success {
				successCount++
			} else {
				failCount++
			}
		}

		totalCount := successCount + failCount
		if totalCount > 0 {
			// Calculate current ratio
			currentSuccessRatio := float64(successCount) / float64(totalCount)

			// Define the maximum ratio (80:20 rule)
			maxRatio := 0.8
			minRatio := 1.0 - maxRatio // 0.2

			// Check if adding this sample would increase imbalance
			wouldIncreaseBias := false

			if success && currentSuccessRatio >= maxRatio {
				// Too many successful samples already, and trying to add another successful one
				wouldIncreaseBias = true
			} else if !success && currentSuccessRatio <= minRatio {
				// Too many failed samples already, and trying to add another failed one
				wouldIncreaseBias = true
			}

			if wouldIncreaseBias {
				// Skip recording to prevent further imbalance
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Skipped recording %s login for training to maintain balance (current ratio: %.1f%% successful)",
						map[bool]string{true: "successful", false: "failed"}[success],
						currentSuccessRatio*100),
				)

				return nil
			}
		}
	}

	// If we reach here, it's safe to record the sample
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	err = rediscli.GetClient().GetWriteHandle().LPush(ctx, key, jsonBytes).Err()
	if err != nil {
		return err
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Get the maximum number of training records from config or use default
	maxRecords := int64(10000) // Default value for backward compatibility
	nnConfig := config.GetFile().GetBruteForce().GetNeuralNetwork()
	if nnConfig != nil {
		configMaxRecords := nnConfig.GetMaxTrainingRecords()
		if configMaxRecords > 0 {
			maxRecords = int64(configMaxRecords)
		}
	}

	// Trim the list to keep only the last maxRecords entries
	err = rediscli.GetClient().GetWriteHandle().LTrim(ctx, key, 0, maxRecords-1).Err()
	if err != nil {
		return err
	}

	return nil
}

// RecordFeedback records user feedback on a prediction for future training.
// This function is used to create a feedback loop for improving detection accuracy.
// Unlike RecordLoginResult, this function does not check for balance in the training data,
// as feedback is considered more valuable and should always be recorded.
//
// Parameters:
// - ctx: The context for the request
// - isBruteForce: Whether the login attempt was actually part of a brute force attack (true) or not (false)
// - features: The features used for the prediction
// - clientIP: The client IP address
// - username: The username being authenticated
// - guid: The unique identifier for the request
//
// Returns an error if the feedback could not be recorded.
func RecordFeedback(ctx context.Context, isBruteForce bool, features *LoginFeatures, clientIP string, username string, guid string) error {
	// Check if experimental ML is enabled
	if !config.GetEnvironment().GetExperimentalML() {
		util.DebugModule(definitions.DbgNeural,
			"action", "skip_record_feedback",
			"reason", "experimental_ml_not_enabled",
			definitions.LogKeyGUID, guid,
		)

		return nil
	}

	// Check if the IP should be ignored for ML training
	if ShouldIgnoreIP(clientIP, username, guid) {
		return nil
	}

	// Store the feedback as training data
	data := TrainingData{
		Success:  !isBruteForce, // Success is the opposite of isBruteForce (success means not a brute force attack)
		Features: features,
		Time:     time.Now(),
		Feedback: true, // Mark this as feedback data
	}

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:training:data"

	// Log the feedback
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Recording user feedback: %s login", map[bool]string{true: "brute force", false: "legitimate"}[isBruteForce]),
		"client_ip", clientIP,
		"username", username,
		definitions.LogKeyGUID, guid,
	)

	// Serialize the data
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Store the feedback at the beginning of the list (most recent)
	err = rediscli.GetClient().GetWriteHandle().LPush(ctx, key, jsonBytes).Err()
	if err != nil {
		return err
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Get the maximum number of training records from config or use default
	maxRecords := int64(10000) // Default value for backward compatibility
	nnConfig := config.GetFile().GetBruteForce().GetNeuralNetwork()
	if nnConfig != nil {
		configMaxRecords := nnConfig.GetMaxTrainingRecords()
		if configMaxRecords > 0 {
			maxRecords = int64(configMaxRecords)
		}
	}

	// Trim the list to keep only the last maxRecords entries
	err = rediscli.GetClient().GetWriteHandle().LTrim(ctx, key, 0, maxRecords-1).Err()
	if err != nil {
		return err
	}

	// Trigger immediate retraining if there's enough feedback
	go func() {
		// Use a background context for the retraining
		bgCtx := context.Background()

		// Get the global trainer
		globalTrainerMutex.RLock()
		trainer := globalTrainer
		globalTrainerMutex.RUnlock()

		if trainer == nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, "Cannot retrain model: global trainer is nil",
			)

			return
		}

		// Check when the last training occurred
		lastTrainingTime, err := GetLastTrainingTime(bgCtx)
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to get last training time: %v", err),
			)

			return
		} else if !lastTrainingTime.IsZero() {
			// If last training was less than 3 hours ago, skip this training
			// For feedback-triggered training, we use a shorter interval than scheduled training
			// because feedback is more valuable and time-sensitive, but still need to prevent loops
			minInterval := 3 * time.Hour
			timeSinceLastTraining := time.Since(lastTrainingTime)

			if timeSinceLastTraining < minInterval {
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, "Skipping feedback-triggered training - too soon since last training",
					"last_training", lastTrainingTime.Format(time.RFC3339),
					"time_since", timeSinceLastTraining.String(),
					"min_interval", minInterval.String(),
				)

				return
			}

			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Sufficient time has passed since last training",
				"last_training", lastTrainingTime.Format(time.RFC3339),
				"time_since", timeSinceLastTraining.String(),
			)
		}

		// Count how many feedback samples we have
		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		// Get a sample of training data to check how many have feedback
		trainingData, err := trainer.GetTrainingDataFromRedis(1000)
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to get training data for feedback check: %v", err),
			)

			return
		}

		// Count feedback samples
		feedbackCount := 0
		for _, sample := range trainingData {
			if sample.Feedback {
				feedbackCount++
			}
		}

		// If we have at least 10 feedback samples, retrain the model
		if feedbackCount >= 10 {
			// Try to acquire the distributed training lock
			// Use a reasonable timeout to prevent deadlocks (30 minutes should be enough for training)
			lockAcquired, lockErr := AcquireTrainingLock(bgCtx, 30*time.Minute)
			if lockErr != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to acquire training lock: %v", lockErr),
				)

				return
			}

			if !lockAcquired {
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, "Skipping feedback-triggered training - another instance is already training",
				)

				return
			}

			// We have the lock, proceed with training
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Retraining model with %d feedback samples", feedbackCount),
			)

			// Start a goroutine to periodically extend the lock TTL during training
			// This prevents the lock from expiring if training takes longer than expected
			heartbeatCtx, heartbeatCancel := context.WithCancel(bgCtx)
			defer heartbeatCancel() // Ensure the heartbeat stops when we're done

			heartbeatDone := make(chan struct{})
			go func() {
				defer close(heartbeatDone)
				ticker := time.NewTicker(5 * time.Minute) // Extend every 5 minutes
				defer ticker.Stop()

				for {
					select {
					case <-ticker.C:
						// Extend the lock TTL
						extended, err := ExtendTrainingLock(heartbeatCtx, 30*time.Minute)
						if err != nil {
							level.Error(log.Logger).Log(
								definitions.LogKeyMsg, fmt.Sprintf("Failed to extend training lock: %v", err),
							)
						} else if !extended {
							level.Warn(log.Logger).Log(
								definitions.LogKeyMsg, "Failed to extend training lock - may have been lost",
							)
						}
					case <-heartbeatCtx.Done():
						return
					}
				}
			}()

			// Train with all available data, with more epochs for better learning
			trainErr := trainer.TrainWithStoredData(5000, 100)

			// Stop the heartbeat goroutine
			heartbeatCancel()
			<-heartbeatDone // Wait for the heartbeat goroutine to finish

			if trainErr != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Feedback-triggered training failed: %v", trainErr),
				)

				// Release the lock since training failed
				if releaseErr := ReleaseTrainingLock(bgCtx); releaseErr != nil {
					level.Error(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Failed to release training lock: %v", releaseErr),
					)
				}

				return
			}

			// Save the trained model to Redis
			saveErr := trainer.SaveModelToRedis()
			if saveErr != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to save model to Redis after feedback training: %v", saveErr),
				)

				// Release the lock since saving failed
				if releaseErr := ReleaseTrainingLock(bgCtx); releaseErr != nil {
					level.Error(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Failed to release training lock: %v", releaseErr),
					)
				}

				return
			}

			// Update the last training timestamp
			if timeErr := SetLastTrainingTime(bgCtx); timeErr != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to update last training time: %v", timeErr),
				)
				// Continue despite error - this just means next training might happen sooner than optimal
			}

			// Publish model update notification to other instances
			pubErr := PublishModelUpdate(bgCtx)
			if pubErr != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to publish model update notification: %v", pubErr),
				)
				// Continue despite error - other instances will still work, just won't get the update notification
			}

			// Release the training lock
			if releaseErr := ReleaseTrainingLock(bgCtx); releaseErr != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to release training lock: %v", releaseErr),
				)
			}

			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Model successfully retrained with feedback data",
			)

			// Set the modelTrained flag if it's not already set
			modelTrainedMutex.RLock()
			isModelTrained := modelTrained
			modelTrainedMutex.RUnlock()

			if !isModelTrained {
				modelTrainedMutex.Lock()
				modelTrained = true
				modelTrainedMutex.Unlock()

				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, "Model is now considered trained with feedback data",
				)

				// Save the flag to Redis for future use
				if saveErr := SaveModelTrainedFlagToRedis(bgCtx); saveErr != nil {
					level.Error(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Failed to save model trained flag to Redis: %v", saveErr),
					)
				}
			}
		} else {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Not enough feedback samples for retraining (%d/10 required)", feedbackCount),
			)
		}
	}()

	return nil
}
