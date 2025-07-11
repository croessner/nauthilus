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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
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

const (
	// OneHotEncoding represents one-hot encoding for string features
	OneHotEncoding StringEncodingType = "one-hot"

	// EmbeddingEncoding represents embedding encoding for string features
	EmbeddingEncoding StringEncodingType = "embedding"
)

// LoginFeatures represents the features used for brute force detection
type LoginFeatures struct {
	// Time between login attempts in seconds
	TimeBetweenAttempts float64

	// Number of failed attempts in the last hour
	FailedAttemptsLastHour float64

	// Number of different usernames tried from the same IP
	DifferentUsernames float64

	// Number of different passwords tried for the same username
	DifferentPasswords float64

	// Time of day (normalized to 0-1)
	TimeOfDay float64

	// Is the IP address from a known suspicious network
	SuspiciousNetwork float64

	// Additional features that can be provided from outside
	AdditionalFeatures map[string]any
}

// GetAdditionalFeaturesRedisKey returns the Redis key for additional features
func GetAdditionalFeaturesRedisKey() string {
	return getMLGlobalKeyPrefix() + "additional_features"
}

// GetFeatureListRedisKey returns the Redis key for the canonical list of dynamic features
// This key is shared across all instances to ensure all instances have access to the same canonical list
func GetFeatureListRedisKey() string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:common:additional_features:list"
}

func (d *BruteForceMLDetector) getLoginTimeKey() string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:login:time:" + d.clientIP
}

func (d *BruteForceMLDetector) getFailedAttemptsKey() string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:failed:attempts:" + d.clientIP
}

// ResetModelToCanonicalFeatures resets the model to use only the features in the canonical list
// This is used to fix issues where the model's input size has grown too large
func ResetModelToCanonicalFeatures(ctx context.Context) error {
	// Get Redis client
	redisClient := rediscli.GetClient().GetWriteHandle()
	if redisClient == nil {
		return fmt.Errorf("failed to get Redis client for resetting model")
	}

	// Get the canonical list of features from Redis
	canonicalFeatures, err := GetDynamicFeaturesFromRedis(ctx)
	if err != nil {
		return fmt.Errorf("failed to get canonical features from Redis: %w", err)
	}

	// Create a temporary trainer to calculate neuron counts
	tempTrainer := NewMLTrainer().WithContext(ctx)

	// Calculate the expected input size: 6 standard features + neurons for canonical features
	expectedInputSize := 6
	additionalNeuronCount := 0

	// Calculate the actual neuron count for each feature
	for _, featureName := range canonicalFeatures {
		neuronCount := tempTrainer.calculateFeatureNeuronCount(featureName)
		additionalNeuronCount += neuronCount

		util.DebugModule(definitions.DbgNeural,
			"action", "reset_model_calculate_feature_neurons",
			"feature_name", featureName,
			"encoding_type", tempTrainer.GetFeatureEncodingType(featureName),
			"neuron_count", neuronCount,
		)
	}

	// Add the total neuron count to the input size
	expectedInputSize += additionalNeuronCount

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Resetting model to use %d input neurons (%d standard + %d dynamic from %d features) based on canonical feature list",
			expectedInputSize, 6, additionalNeuronCount, len(canonicalFeatures)),
		"features", strings.Join(canonicalFeatures, ", "),
	)

	// Create a new model with the correct input size
	newModel := NewNeuralNetwork(expectedInputSize, 1)

	// Ensure metrics are updated with the correct input size
	GetMLMetrics().RecordNetworkStructure(expectedInputSize, newModel.hiddenSize, 1)

	// Set the model in the temporary trainer
	tempTrainer.model = newModel

	// Save the new model to Redis
	if err := tempTrainer.SaveModelToRedis(); err != nil {
		return fmt.Errorf("failed to save reset model to Redis: %w", err)
	}

	// Publish a model update notification to ensure all instances are aware of the reset
	if err := PublishModelUpdate(ctx); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to publish model update notification after reset: %v", err),
		)
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Successfully reset model to canonical features",
	)

	return nil
}

// RemoveFeaturesFromRedis removes the specified features from the canonical list in Redis
// This ensures all instances have access to the same updated canonical list of features
// It also publishes a model update notification to ensure all instances are aware of the removal
func RemoveFeaturesFromRedis(ctx context.Context, featuresToRemove []string) error {
	// Get Redis client
	redisClient := rediscli.GetClient().GetWriteHandle()
	if redisClient == nil {
		return fmt.Errorf("failed to get Redis client for removing dynamic features")
	}

	// Get the key for the feature list
	key := GetFeatureListRedisKey()

	// Skip if no features to remove
	if len(featuresToRemove) == 0 {
		return nil
	}

	// Convert features to remove to interface slice for Redis SREM command
	args := make([]any, len(featuresToRemove))
	for i, feature := range featuresToRemove {
		args[i] = feature
	}

	// Remove the features from the set
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()
	removed, err := redisClient.SRem(ctx, key, args...).Result()
	if err != nil {
		return fmt.Errorf("failed to remove dynamic features from Redis: %w", err)
	}

	// Log the number of features removed
	if removed > 0 {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Removed %d features from canonical list: %s",
				removed, strings.Join(featuresToRemove, ", ")),
		)

		// Reset the model to use the updated canonical features
		if err := ResetModelToCanonicalFeatures(ctx); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to reset model after removing features: %v", err),
			)
		}

		// Publish a model update notification to ensure all instances are aware of the removal
		if err := PublishModelUpdate(ctx); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to publish model update notification after removing features: %v", err),
			)
		} else {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Successfully published model update notification for removed features",
			)
		}
	} else {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "No features were removed from canonical list (features not found)",
		)
	}

	return nil
}

// StoreDynamicFeaturesToRedis stores the list of dynamic features to Redis
// This ensures all instances have access to the same canonical list of features
// It also publishes a model update notification if new features were added
func StoreDynamicFeaturesToRedis(ctx context.Context, features []string) error {
	// Get Redis client
	redisClient := rediscli.GetClient().GetWriteHandle()
	if redisClient == nil {
		return fmt.Errorf("failed to get Redis client for storing dynamic features")
	}

	// Store the features as a set in Redis
	key := GetFeatureListRedisKey()

	// First, get the existing features to check if we're adding new ones
	defer stats.GetMetrics().GetRedisReadCounter().Inc()
	existingFeatures, err := rediscli.GetClient().GetReadHandle().SMembers(ctx, key).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("failed to retrieve existing dynamic features from Redis: %w", err)
	}

	// Track if we're adding new features
	existingMap := make(map[string]bool)
	for _, feature := range existingFeatures {
		existingMap[feature] = true
	}

	var newFeatures []string
	for _, feature := range features {
		if !existingMap[feature] {
			newFeatures = append(newFeatures, feature)
		}
	}

	// Use SADD to add all features to the set
	if len(features) > 0 {
		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		args := make([]any, len(features))
		for i, feature := range features {
			args[i] = feature
		}

		_, err := redisClient.SAdd(ctx, key, args...).Result()
		if err != nil {
			return fmt.Errorf("failed to store dynamic features to Redis: %w", err)
		}

		// If we added new features, publish a model update notification
		if len(newFeatures) > 0 {
			// Get the total number of features after adding the new ones
			totalFeatures := len(existingFeatures) + len(newFeatures)

			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Added %d new features to canonical list: %s (total: %d)",
					len(newFeatures), strings.Join(newFeatures, ", "), totalFeatures),
			)

			// Publish a model update notification to ensure all instances are aware of the new features
			if err := PublishModelUpdate(ctx); err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to publish model update notification after adding new features: %v", err),
				)
			} else {
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, "Successfully published model update notification for new features",
				)
			}
		}
	}

	return nil
}

// GetDynamicFeaturesFromRedis retrieves the canonical list of dynamic features from Redis
func GetDynamicFeaturesFromRedis(ctx context.Context) ([]string, error) {
	// Get Redis client
	redisClient := rediscli.GetClient().GetReadHandle()
	if redisClient == nil {
		return nil, fmt.Errorf("failed to get Redis client for retrieving dynamic features")
	}

	// Get the features from Redis
	key := GetFeatureListRedisKey()

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	features, err := redisClient.SMembers(ctx, key).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("failed to retrieve dynamic features from Redis: %w", err)
	}

	// Log the number of features for monitoring
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Retrieved %d dynamic features from canonical list", len(features)),
	)

	return features, nil
}

// SetAdditionalFeatures sets additional features for the detector
func (d *BruteForceMLDetector) SetAdditionalFeatures(features map[string]any) {
	// Get encoding type preferences from the context if they exist
	var encodingTypes map[string]string

	if exists, ok := d.ctx.Value(definitions.CtxFeatureEncodingTypeKey).(map[string]string); ok {
		encodingTypes = exists
	}

	// Store feature names in the canonical list in Redis
	if features != nil && len(features) > 0 {
		// Extract feature names
		featureNames := make([]string, 0, len(features))
		for key := range features {
			featureNames = append(featureNames, key)
		}

		// Store feature names in Redis
		if err := StoreDynamicFeaturesToRedis(d.ctx, featureNames); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, d.guid,
				definitions.LogKeyMsg, fmt.Sprintf("Failed to store dynamic features to Redis: %v", err),
			)
		} else {
			level.Info(log.Logger).Log(
				definitions.LogKeyGUID, d.guid,
				definitions.LogKeyMsg, fmt.Sprintf("Stored %d dynamic features to canonical list", len(featureNames)),
				"features", strings.Join(featureNames, ", "),
			)
		}
	}

	// Check if we need to reinitialize the model due to new additional features
	if d.model != nil && features != nil && len(features) > 0 {
		// Calculate the expected input size based on standard features (6) plus additional features
		// For string features, we need to account for embedding size if embedding encoding is used
		expectedInputSize := 6

		// Get the global trainer to access embedding size
		globalTrainerMutex.RLock()
		trainer := globalTrainer
		globalTrainerMutex.RUnlock()

		// Calculate expected input size based on feature types and encoding preferences
		for key, value := range features {
			if _, isString := value.(string); isString {
				// Check if we have an encoding preference for this feature
				encodingType := "one-hot" // Default to one-hot
				if encodingTypes != nil {
					if et, ok := encodingTypes[key]; ok {
						encodingType = et
					}
				}

				if encodingType == "embedding" && trainer != nil {
					// For embedding encoding, add the embedding size
					expectedInputSize += trainer.embeddingSize

					// Set the encoding type in the trainer
					trainer.SetFeatureEncodingType(key, EmbeddingEncoding)
				} else {
					// For one-hot encoding, check if we already have values in oneHotSizes
					if trainer != nil {
						trainer.SetFeatureEncodingType(key, OneHotEncoding)

						// Check if we have existing one-hot sizes for this feature
						if size, exists := trainer.oneHotSizes[key]; exists && size > 0 {
							// Use the actual number of possible values
							expectedInputSize += size

							util.DebugModule(definitions.DbgNeural,
								"action", "calculate_one_hot_size_from_existing",
								"feature_name", key,
								"one_hot_size", size,
								definitions.LogKeyGUID, d.guid,
							)
						} else {
							// No existing values, add 1 (we'll expand it later in Predict)
							expectedInputSize += 1

							util.DebugModule(definitions.DbgNeural,
								"action", "using_default_one_hot_size",
								"feature_name", key,
								"one_hot_size", 1,
								definitions.LogKeyGUID, d.guid,
							)
						}
					} else {
						// No trainer available, add 1
						expectedInputSize += 1
					}
				}
			} else {
				// For non-string features, add 1
				expectedInputSize += 1
			}
		}

		// If the model's input size is smaller than what we need, we need to reinitialize
		if d.model.inputSize < expectedInputSize {
			util.DebugModule(definitions.DbgNeural,
				"action", "reinitialize_model_for_additional_features",
				"current_input_size", d.model.inputSize,
				"expected_input_size", expectedInputSize,
				"additional_features_count", len(features),
				definitions.LogKeyGUID, d.guid,
			)

			// We need to reinitialize the global model to handle the new features
			globalTrainerMutex.RLock()
			trainerExists := globalTrainer != nil
			globalTrainerMutex.RUnlock()

			if trainerExists {
				// Create a new model with the correct input size
				newModel := NewNeuralNetwork(expectedInputSize, 1)

				// First try to load a model with additional features from the separate Redis key
				tempTrainer := NewMLTrainer().WithContext(d.ctx)
				err := tempTrainer.LoadAdditionalFeaturesFromRedis()

				// Flag to track if we found a suitable saved model with additional features
				useSavedAdditionalFeatures := err == nil && tempTrainer.model != nil && tempTrainer.model.inputSize >= expectedInputSize

				if useSavedAdditionalFeatures {
					util.DebugModule(definitions.DbgNeural,
						"action", "using_saved_additional_features",
						"saved_model_input_size", tempTrainer.model.inputSize,
						"expected_input_size", expectedInputSize,
						definitions.LogKeyGUID, d.guid,
					)
				} else {
					// If no additional features model found, try the main model as fallback
					err = tempTrainer.LoadModelFromRedis()

					// Flag to track if we found a suitable saved model
					useSavedWeights := err == nil && tempTrainer.model != nil && tempTrainer.model.inputSize >= expectedInputSize

					if useSavedWeights {
						util.DebugModule(definitions.DbgNeural,
							"action", "using_saved_weights_for_additional_features",
							"saved_model_input_size", tempTrainer.model.inputSize,
							"expected_input_size", expectedInputSize,
							definitions.LogKeyGUID, d.guid,
						)
					} else {
						// No suitable saved model found, initialize with random weights
						util.DebugModule(definitions.DbgNeural,
							"action", "using_random_weights_for_additional_features",
							"reason", "no_suitable_saved_model",
							"error", fmt.Sprintf("%v", err),
							definitions.LogKeyGUID, d.guid,
						)
					}
				}

				// Copy weights and biases for existing connections where possible
				// For input to hidden layer
				for i := 0; i < d.model.hiddenSize; i++ {
					// Copy weights for existing connections
					for j := 0; j < d.model.inputSize; j++ {
						oldWeightIndex := i*d.model.inputSize + j
						newWeightIndex := i*expectedInputSize + j

						if oldWeightIndex < len(d.model.weights) && newWeightIndex < len(newModel.weights) {
							newModel.weights[newWeightIndex] = d.model.weights[oldWeightIndex]
						}
					}

					// Initialize weights for new connections
					for j := d.model.inputSize; j < expectedInputSize; j++ {
						newWeightIndex := i*expectedInputSize + j

						if useSavedAdditionalFeatures {
							// Use weights from the saved additional features model for the new connections
							savedWeightIndex := i*tempTrainer.model.inputSize + j

							if savedWeightIndex < len(tempTrainer.model.weights) && newWeightIndex < len(newModel.weights) {
								newModel.weights[newWeightIndex] = tempTrainer.model.weights[savedWeightIndex]
							}
						} else {
							// Initialize with random weights
							if newWeightIndex < len(newModel.weights) {
								newModel.weights[newWeightIndex] = (newModel.rng.Float64() - 0.5) * 0.1
							}
						}
					}

					// Copy hidden layer bias
					if i < len(d.model.hiddenBias) && i < len(newModel.hiddenBias) {
						newModel.hiddenBias[i] = d.model.hiddenBias[i]
					}
				}

				// For hidden to output layer
				hiddenToOutputOffset := d.model.inputSize * d.model.hiddenSize
				newHiddenToOutputOffset := expectedInputSize * newModel.hiddenSize

				for i := 0; i < d.model.outputSize; i++ {
					for j := 0; j < d.model.hiddenSize; j++ {
						oldWeightIndex := hiddenToOutputOffset + i*d.model.hiddenSize + j
						newWeightIndex := newHiddenToOutputOffset + i*newModel.hiddenSize + j

						if oldWeightIndex < len(d.model.weights) && newWeightIndex < len(newModel.weights) {
							newModel.weights[newWeightIndex] = d.model.weights[oldWeightIndex]
						}
					}

					// Copy output layer bias
					if i < len(d.model.outputBias) && i < len(newModel.outputBias) {
						newModel.outputBias[i] = d.model.outputBias[i]
					}
				}

				// Update the global trainer's model
				globalTrainerMutex.Lock()
				if globalTrainer != nil {
					globalTrainer.model = newModel
				}
				globalTrainerMutex.Unlock()

				// Update this detector's model
				d.model = newModel

				// Ensure metrics are updated with the correct input size
				GetMLMetrics().RecordNetworkStructure(expectedInputSize, newModel.hiddenSize, 1)

				level.Info(log.Logger).Log(
					definitions.LogKeyGUID, d.guid,
					definitions.LogKeyMsg, fmt.Sprintf("Reinitialized neural network model to handle %d additional features (new input size: %d)", len(features), expectedInputSize),
				)

				// Schedule a training to optimize the new weights
				// Skip training during tests to avoid Redis errors
				if os.Getenv("NAUTHILUS_TESTING") != "1" {
					go func() {
						// Get a local copy of globalTrainer
						globalTrainerMutex.RLock()
						localTrainer := globalTrainer
						globalTrainerMutex.RUnlock()

						if localTrainer == nil {
							level.Error(log.Logger).Log(
								definitions.LogKeyMsg, "Cannot train model: global trainer is nil",
							)

							return
						}

						// Try to acquire the distributed training lock
						// Use a reasonable timeout to prevent deadlocks (30 minutes should be enough for training)
						lockAcquired, lockErr := AcquireTrainingLock(d.ctx, 30*time.Minute)
						if lockErr != nil {
							level.Error(log.Logger).Log(
								definitions.LogKeyMsg, fmt.Sprintf("Failed to acquire training lock: %v", lockErr),
							)

							return
						}

						if !lockAcquired {
							level.Info(log.Logger).Log(
								definitions.LogKeyMsg, "Skipping training after feature reinitialization - another instance is already training",
							)

							return
						}

						// We have the lock, proceed with training

						// Start a goroutine to periodically extend the lock TTL during training
						// This prevents the lock from expiring if training takes longer than expected
						heartbeatCtx, heartbeatCancel := context.WithCancel(d.ctx)
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

						// Train the model
						err := localTrainer.TrainWithStoredData(1000, 20)

						// Stop the heartbeat goroutine
						heartbeatCancel()
						<-heartbeatDone // Wait for the heartbeat goroutine to finish

						if err != nil {
							level.Error(log.Logger).Log(
								definitions.LogKeyMsg, fmt.Sprintf("Failed to train model after reinitializing for additional features: %v", err),
							)

							// Release the lock since training failed
							if releaseErr := ReleaseTrainingLock(d.ctx); releaseErr != nil {
								level.Error(log.Logger).Log(
									definitions.LogKeyMsg, fmt.Sprintf("Failed to release training lock: %v", releaseErr),
								)
							}

							return
						} else {
							// Reset the model to use the canonical features from Redis
							if err := ResetModelToCanonicalFeatures(context.Background()); err != nil {
								level.Error(log.Logger).Log(
									definitions.LogKeyMsg, fmt.Sprintf("Failed to reset model to canonical features after training: %v", err),
								)
							} else {
								level.Info(log.Logger).Log(
									definitions.LogKeyMsg, "Successfully reset model to canonical features after training",
								)

								// Save the trained model to both Redis keys
								if err := localTrainer.SaveModelToRedis(); err != nil {
									level.Error(log.Logger).Log(
										definitions.LogKeyMsg, fmt.Sprintf("Failed to save reinitialized model to Redis: %v", err),
									)
								}

								// Also save to the additional features key
								if err := localTrainer.SaveAdditionalFeaturesToRedis(); err != nil {
									level.Error(log.Logger).Log(
										definitions.LogKeyMsg, fmt.Sprintf("Failed to save additional features model to Redis: %v", err),
									)
								}
							}
						}

						// Release the training lock
						if releaseErr := ReleaseTrainingLock(d.ctx); releaseErr != nil {
							level.Error(log.Logger).Log(
								definitions.LogKeyMsg, fmt.Sprintf("Failed to release training lock: %v", releaseErr),
							)
						}
					}()
				}
			}
		}
	}

	// Set the additional features
	d.additionalFeatures = features

	// Store the encoding types in the detector
	d.featureEncodingTypes = encodingTypes
}

// CollectFeatures gathers the necessary features for the ML model
func (d *BruteForceMLDetector) CollectFeatures() (*LoginFeatures, error) {
	util.DebugModule(definitions.DbgNeural,
		"action", "collect_features_start",
		definitions.LogKeyGUID, d.guid,
		definitions.LogKeyClientIP, d.clientIP,
		definitions.LogKeyUsername, d.username,
	)

	features := &LoginFeatures{}

	// Get the last login attempt time for this IP

	lastAttemptTime, err := d.getLastLoginAttemptTime()
	if err != nil {
		return nil, err
	}

	// Calculate time between attempts
	if !lastAttemptTime.IsZero() {
		features.TimeBetweenAttempts = time.Since(lastAttemptTime).Seconds()

		util.DebugModule(definitions.DbgNeural,
			"action", "collect_features_time_between_attempts",
			"seconds", features.TimeBetweenAttempts,
			"last_attempt", lastAttemptTime.Format(time.RFC3339),
			definitions.LogKeyGUID, d.guid,
		)
	} else {
		features.TimeBetweenAttempts = 3600 // Default to 1 hour if first attempt

		util.DebugModule(definitions.DbgNeural,
			"action", "collect_features_time_between_attempts_default",
			"seconds", features.TimeBetweenAttempts,
			definitions.LogKeyGUID, d.guid,
		)
	}

	// Store current attempt time
	if err := d.storeLoginAttemptTime(); err != nil {
		return nil, err
	}

	// Get failed attempts in the last hour
	failedAttempts, err := d.getFailedAttemptsLastHour()
	if err != nil {
		return nil, err
	}

	features.FailedAttemptsLastHour = float64(failedAttempts)

	util.DebugModule(definitions.DbgNeural,
		"action", "collect_features_failed_attempts",
		"count", failedAttempts,
		definitions.LogKeyGUID, d.guid,
	)

	// Get different usernames tried from this IP
	util.DebugModule(definitions.DbgNeural,
		"action", "collect_features_get_different_usernames",
		definitions.LogKeyGUID, d.guid,
	)

	differentUsernames, err := d.getDifferentUsernames()
	if err != nil {
		return nil, err
	}

	features.DifferentUsernames = float64(differentUsernames)

	util.DebugModule(definitions.DbgNeural,
		"action", "collect_features_different_usernames",
		"count", differentUsernames,
		definitions.LogKeyGUID, d.guid,
	)

	// Get different passwords tried for this username
	differentPasswords, err := d.getDifferentPasswords()
	if err != nil {
		return nil, err
	}

	features.DifferentPasswords = float64(differentPasswords)

	util.DebugModule(definitions.DbgNeural,
		"action", "collect_features_different_passwords",
		"count", differentPasswords,
		definitions.LogKeyGUID, d.guid,
	)

	// Calculate time of day (normalized to 0-1)
	hour := float64(time.Now().Hour())
	features.TimeOfDay = hour / 24.0

	util.DebugModule(definitions.DbgNeural,
		"action", "collect_features_time_of_day",
		"hour", hour,
		"normalized", features.TimeOfDay,
		definitions.LogKeyGUID, d.guid,
	)

	// Check if IP is from a suspicious network

	suspicious, err := d.isFromSuspiciousNetwork()
	if err != nil {
		return nil, err
	}

	if suspicious {
		features.SuspiciousNetwork = 1.0
		util.DebugModule(definitions.DbgNeural,
			"action", "collect_features_suspicious_network",
			"is_suspicious", true,
			definitions.LogKeyGUID, d.guid,
		)
	} else {
		features.SuspiciousNetwork = 0.0

		util.DebugModule(definitions.DbgNeural,
			"action", "collect_features_suspicious_network",
			"is_suspicious", false,
			definitions.LogKeyGUID, d.guid,
		)
	}

	// Initialize additional features if not already initialized
	if d.additionalFeatures == nil {
		d.additionalFeatures = make(map[string]any)
	}

	// Always set AdditionalFeatures, even if empty
	features.AdditionalFeatures = d.additionalFeatures

	util.DebugModule(definitions.DbgNeural,
		"action", "collect_features_additional",
		"additional_features_count", len(d.additionalFeatures),
		definitions.LogKeyGUID, d.guid,
	)

	util.DebugModule(definitions.DbgNeural,
		"action", "collect_features_complete",
		"time_between_attempts", features.TimeBetweenAttempts,
		"failed_attempts", features.FailedAttemptsLastHour,
		"different_usernames", features.DifferentUsernames,
		"different_passwords", features.DifferentPasswords,
		"time_of_day", features.TimeOfDay,
		"suspicious_network", features.SuspiciousNetwork,
		definitions.LogKeyGUID, d.guid,
	)

	return features, nil
}

func (d *BruteForceMLDetector) getLastLoginAttemptTime() (time.Time, error) {
	key := d.getLoginTimeKey()

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	val, err := rediscli.GetClient().GetReadHandle().Get(d.ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return time.Time{}, nil // No previous login attempt
		}

		return time.Time{}, err
	}

	timestamp, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return time.Time{}, err
	}

	return timestamp, nil
}

func (d *BruteForceMLDetector) storeLoginAttemptTime() error {
	key := d.getLoginTimeKey()

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	err := rediscli.GetClient().GetWriteHandle().Set(
		d.ctx,
		key,
		time.Now().Format(time.RFC3339),
		24*time.Hour, // 24 hour TTL
	).Err()

	return err
}

func (d *BruteForceMLDetector) getFailedAttemptsLastHour() (uint, error) {
	key := d.getFailedAttemptsKey()

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	val, err := rediscli.GetClient().GetReadHandle().Get(d.ctx, key).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil // No failed attempts
		}

		return 0, err
	}

	return uint(val), nil
}

func (d *BruteForceMLDetector) incrementFailedAttempts() error {
	key := d.getFailedAttemptsKey()

	// Use Lua script to increment counter and set expiration atomically
	_, err := rediscli.ExecuteScript(
		d.ctx,
		"IncrementAndExpire",
		rediscli.LuaScripts["IncrementAndExpire"],
		[]string{key},
		3600, // 1 hour in seconds
	)

	if err != nil {
		return err
	}

	return nil
}

func (d *BruteForceMLDetector) getDifferentUsernames() (uint, error) {
	// This method tracks and returns the number of different usernames tried from this IP address
	// It uses a Redis Set to store unique usernames and returns the cardinality of the set

	// Get the key for storing usernames tried from this IP
	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:usernames:" + d.clientIP

	// Add the current username to the set if it's not empty
	if d.username != "" {
		// Use Lua script to add username to set and set expiration atomically
		_, err := rediscli.ExecuteScript(
			d.ctx,
			"AddToSetAndExpire",
			rediscli.LuaScripts["AddToSetAndExpire"],
			[]string{key},
			d.username,
			3600, // 1 hour in seconds
		)

		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, d.guid,
				definitions.LogKeyMsg, fmt.Sprintf("Failed to add username to set: %v", err),
			)

			return 0, err
		}
	}

	// Get the set size (number of different usernames)
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	count, err := rediscli.GetClient().GetReadHandle().SCard(d.ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// If the key doesn't exist, there are no usernames yet
			return 0, nil
		}

		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, d.guid,
			definitions.LogKeyMsg, fmt.Sprintf("Failed to get username set size: %v", err),
		)

		return 0, err
	}

	// Log the number of different usernames for debugging
	util.DebugModule(
		definitions.DbgNeural,
		definitions.LogKeyGUID, d.guid,
		definitions.LogKeyClientIP, d.clientIP,
		definitions.LogKeyMsg, fmt.Sprintf("Number of different usernames tried: %d", count),
	)

	return uint(count), nil
}

func (d *BruteForceMLDetector) getDifferentPasswords() (uint, error) {
	// This method retrieves the number of different passwords tried for this username
	// It uses the existing password history implementation in bruteforce.go

	// If username is empty, we can't get password history for a specific user
	if d.username == "" {
		return 0, nil
	}

	// Generate the Redis key for password history with username
	// Following the same pattern as in bruteforce.go's getPasswordHistoryRedisHashKey
	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisPwHashKey + ":" + d.username + ":" + d.clientIP

	// Get all password hashes from Redis
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	passwordHistory, err := rediscli.GetClient().GetReadHandle().HGetAll(d.ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// If the key doesn't exist, there are no passwords yet
			return 0, nil
		}

		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, d.guid,
			definitions.LogKeyMsg, fmt.Sprintf("Failed to get password history: %v", err),
		)

		return 0, err
	}

	// Count the number of different passwords (keys in the hash)
	count := len(passwordHistory)

	// Log the number of different passwords for debugging
	util.DebugModule(
		definitions.DbgNeural,
		definitions.LogKeyGUID, d.guid,
		definitions.LogKeyClientIP, d.clientIP,
		definitions.LogKeyUsername, d.username,
		definitions.LogKeyMsg, fmt.Sprintf("Number of different passwords tried: %d", count),
	)

	return uint(count), nil
}

func (d *BruteForceMLDetector) isFromSuspiciousNetwork() (bool, error) {
	// Check if the IP is in the blocklist service
	// Create a JSON payload with the client IP
	payload := map[string]string{
		"ip": d.clientIP,
	}

	// Convert the payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, d.guid,
			definitions.LogKeyMsg, fmt.Sprintf("Failed to marshal JSON payload: %v", err),
		)

		return false, err
	}

	// Get the blocklist URL from environment
	blocklistURL := os.Getenv("BLOCKLIST_URL")
	if blocklistURL == "" {
		// If no blocklist URL is configured, skip the check
		level.Debug(log.Logger).Log(
			definitions.LogKeyGUID, d.guid,
			definitions.LogKeyMsg, "No blocklist URL configured, skipping check",
		)

		return false, nil
	}

	// Create a context with timeout for the HTTP request
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)

	defer cancel()

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, blocklistURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, d.guid,
			definitions.LogKeyMsg, fmt.Sprintf("Failed to create HTTP request: %v", err),
		)

		return false, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Nauthilus")
	req.Header.Set("Accept", "*/*")

	resp, err := httpClient.Do(req)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, d.guid,
			definitions.LogKeyMsg, fmt.Sprintf("Failed to send HTTP request: %v", err),
		)

		return false, err
	}

	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, d.guid,
			definitions.LogKeyMsg, fmt.Sprintf("Blocklist service returned non-OK status: %d", resp.StatusCode),
		)

		return false, fmt.Errorf("blocklist service returned status %d", resp.StatusCode)
	}

	// Parse the response
	var response struct {
		Found bool   `json:"found"`
		Error string `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, d.guid,
			definitions.LogKeyMsg, fmt.Sprintf("Failed to decode response: %v", err),
		)

		return false, err
	}

	// Check if there was an error in the response
	if response.Error != "" {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, d.guid,
			definitions.LogKeyMsg, fmt.Sprintf("Blocklist service returned error: %s", response.Error),
		)

		return false, fmt.Errorf("blocklist service error: %s", response.Error)
	}

	// Log the result for debugging
	util.DebugModule(
		definitions.DbgNeural,
		definitions.LogKeyGUID, d.guid,
		definitions.LogKeyClientIP, d.clientIP,
		definitions.LogKeyMsg, fmt.Sprintf("IP in suspicious network: %t", response.Found),
	)

	return response.Found, nil
}
