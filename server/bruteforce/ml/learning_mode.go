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
	"os"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"

	"github.com/go-kit/log/level"
)

// initializeModelAndTrainedFlag initializes and verifies the ML model and its trained status flag.
// It attempts to load a pre-trained model and trained flag from Redis, or initializes with defaults if unavailable.
// Returns true if the model was successfully loaded from Redis, otherwise false.
func initializeModelAndTrainedFlag(ctx context.Context, trainer *NeuralNetworkTrainer) bool {
	// Initialize modelTrained flag to false
	modelTrainedMutex.Lock()
	modelTrained = false
	modelTrainedMutex.Unlock()

	// Try to load the canonical list of dynamic features from Redis
	// This ensures we know about all possible features even before loading the model
	if os.Getenv("NAUTHILUS_TESTING") != "1" {
		canonicalFeatures, err := GetDynamicFeaturesFromRedis(ctx)
		if err != nil {
			level.Warn(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to retrieve canonical feature list from Redis during initialization: %v", err),
			)
		} else if len(canonicalFeatures) > 0 {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Loaded canonical feature list with %d features during initialization", len(canonicalFeatures)),
				"features", strings.Join(canonicalFeatures, ", "),
			)

			// Get existing additional features from context
			var existingFeatures map[string]any
			if exists, ok := ctx.Value(definitions.CtxAdditionalFeaturesKey).(map[string]any); ok {
				existingFeatures = exists
			} else {
				existingFeatures = make(map[string]any)
			}

			// Create a map of canonical features for quick lookup
			canonicalMap := make(map[string]bool)
			for _, feature := range canonicalFeatures {
				canonicalMap[feature] = true
			}

			// Add any missing canonical features to the context and remove any that are no longer in the canonical list
			var addedFeatures []string
			var removedFeatures []string

			// First, identify features to remove (those in existingFeatures but not in canonicalMap)
			for feature := range existingFeatures {
				if !canonicalMap[feature] {
					delete(existingFeatures, feature)
					removedFeatures = append(removedFeatures, feature)
				}
			}

			// Then, add missing features (those in canonicalMap but not in existingFeatures)
			for _, feature := range canonicalFeatures {
				if _, exists := existingFeatures[feature]; !exists {
					existingFeatures[feature] = 0.0
					addedFeatures = append(addedFeatures, feature)
				}
			}

			// Store the updated features in the context
			ctx = context.WithValue(ctx, definitions.CtxAdditionalFeaturesKey, existingFeatures)

			// Log detailed information about added features
			if len(addedFeatures) > 0 {
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Added %d missing features from canonical list during initialization", len(addedFeatures)),
					"features", strings.Join(addedFeatures, ", "),
				)
			}

			// Log detailed information about removed features
			if len(removedFeatures) > 0 {
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Removed %d features that are no longer in canonical list during initialization", len(removedFeatures)),
					"features", strings.Join(removedFeatures, ", "),
				)
			}

			util.DebugModule(definitions.DbgNeural,
				"action", "update_canonical_features_during_initialization",
				"features_added", len(addedFeatures),
				"features_removed", len(removedFeatures),
				"total_features", len(existingFeatures),
			)

			// Update the trainer's context
			trainer.WithContext(ctx)
		}
	}

	// Reset the model to use the canonical features from Redis before loading
	// This ensures that the model will have the correct input size for the canonical features
	if resetErr := ResetModelToCanonicalFeatures(ctx); resetErr != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to reset model to canonical features before loading: %v", resetErr),
		)
		// Continue despite error - we'll still try to load the model
	} else {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Successfully reset model to canonical features before loading",
		)
	}

	// Try to load a previously trained model first
	modelLoadedFromRedis := false
	if loadErr := trainer.LoadModelFromRedis(); loadErr != nil {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("No pre-trained model found, initializing with random weights: %v", loadErr),
		)

		// Initialize the neural network model with random weights as fallback
		trainer.InitModel()
	} else {
		modelLoadedFromRedis = true
	}

	// Try to load the model trained flag from Redis
	if loadFlagErr := LoadModelTrainedFlagFromRedis(ctx); loadFlagErr != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to load model trained flag from Redis: %v", loadFlagErr),
		)

		// If we can't load the flag, check if we have enough training data
		// to consider the model trained
		if modelLoadedFromRedis {
			// Get a sample of training data to check if we have enough
			trainingData, err := trainer.GetTrainingDataFromRedis(100)
			if err == nil && len(trainingData) >= 100 {
				modelTrainedMutex.Lock()
				modelTrained = true
				modelTrainedMutex.Unlock()

				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, "Loaded model is considered trained with real data",
				)

				// Save the flag to Redis for future use
				_ = SaveModelTrainedFlagToRedis(ctx)
			} else {
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, "Loaded model does not have enough training data, starting in learning mode",
				)
			}
		}
	} else {
		// Flag was loaded successfully, log the current state
		modelTrainedMutex.RLock()
		isModelTrained := modelTrained
		modelTrainedMutex.RUnlock()

		if isModelTrained {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Model is marked as trained with real data",
			)
		} else {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Model is in learning mode",
			)
		}
	}

	// Update the last training time during initialization
	// This prevents immediate retraining after system restart
	if modelLoadedFromRedis {
		if err := SetLastTrainingTime(ctx); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to update last training time during initialization: %v", err),
			)
		} else {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Updated last training time during initialization to prevent immediate retraining",
			)
		}
	}

	return modelLoadedFromRedis
}

// learningModeUpdateSubscriber listens to a Redis channel for learning mode updates and updates the system's state accordingly.
// ctx is the context to manage the lifetime of the subscriber.
// stopChan is a channel used to gracefully stop the subscription.
func learningModeUpdateSubscriber(ctx context.Context, stopChan chan struct{}) {
	redisClient := rediscli.GetClient().GetReadHandle()
	if redisClient == nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, "Failed to get Redis client for learning mode update subscription",
		)

		return
	}

	// Subscribe to learning mode update channel
	channel := getLearningModeUpdateChannel()
	pubsub := redisClient.Subscribe(ctx, channel)

	defer pubsub.Close()

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Subscribed to learning mode update notifications",
		"channel", channel,
	)

	// Listen for messages
	for {
		select {
		case <-ctx.Done():
			return
		case <-stopChan:
			return
		case msg := <-pubsub.Channel():
			// Parse message
			var updateMsg map[string]any
			if err := json.Unmarshal([]byte(msg.Payload), &updateMsg); err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to parse learning mode update message: %v", err),
					"payload", msg.Payload,
				)

				continue
			}

			// Skip our own messages
			if instanceName, ok := updateMsg["instance_name"].(string); ok {
				if instanceName == config.GetFile().GetServer().GetInstanceName() {
					util.DebugModule(definitions.DbgNeural,
						"action", "skip_own_learning_mode_update",
					)

					continue
				}
			}

			// Get the learning mode from the message
			learningMode, ok := updateMsg["learning_mode"].(bool)
			if !ok {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, "Learning mode update message has invalid format",
					"payload", msg.Payload,
				)

				continue
			}

			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Received learning mode update notification, updating learning mode",
				"from_instance", updateMsg["instance_name"],
				"learning_mode", learningMode,
			)

			// Update learning mode
			modelTrainedMutex.Lock()
			modelDryRun = learningMode
			modelTrainedMutex.Unlock()

			// Save the updated flag to Redis
			if err := SaveModelTrainedFlagToRedis(ctx); err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to save model trained flags to Redis after update from notification: %v", err),
				)
			}

			util.DebugModule(definitions.DbgNeural,
				"action", "update_learning_mode_from_notification",
				"learning_mode", learningMode,
			)
		}
	}
}

// IsLearningMode returns true if the model is still in learning mode
func (d *BruteForceMLDetector) IsLearningMode() bool {
	modelTrainedMutex.RLock()
	isModelTrained := modelTrained && !modelDryRun
	modelTrainedMutex.RUnlock()

	return !isModelTrained
}

// PublishLearningModeUpdate publishes a message to notify other instances that the learning mode has changed.
// This function is similar to PublishModelUpdate but specifically for learning mode changes.
//
// The function publishes a message to a Redis channel that includes:
// - The timestamp of when the learning mode was changed
// - The name of the instance that changed the learning mode
// - The new learning mode state (enabled/disabled)
//
// Other instances subscribe to this channel and update their learning mode when they receive a notification.
// This ensures that all instances use the same learning mode without having to set it manually on each instance.
//
// Parameters:
// - ctx: The context for the request
// - enabled: The new learning mode state
//
// Returns an error if the message could not be published.
func PublishLearningModeUpdate(ctx context.Context, enabled bool) error {
	// Get Redis client
	redisClient := rediscli.GetClient().GetWriteHandle()
	if redisClient == nil {
		return fmt.Errorf("failed to get Redis client for publishing learning mode update")
	}

	// Create message with timestamp, instance name, and learning mode
	message := map[string]any{
		"timestamp":     time.Now().Unix(),
		"instance_name": config.GetFile().GetServer().GetInstanceName(),
		"learning_mode": enabled,
	}

	// Convert message to JSON
	jsonBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal learning mode update message: %w", err)
	}

	// Publish message to channel
	channel := getLearningModeUpdateChannel()
	err = redisClient.Publish(ctx, channel, jsonBytes).Err()
	if err != nil {
		return fmt.Errorf("failed to publish learning mode update message: %w", err)
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Published learning mode update notification",
		"channel", channel,
		"learning_mode", enabled,
	)

	return nil
}

// SetLearningMode updates the learning mode state for the model based on the given boolean flag and persists the change.
// Returns the updated learning mode state and an error if the operation fails.
func SetLearningMode(ctx context.Context, enabled bool) (bool, error) {
	modelTrainedMutex.Lock()
	modelDryRun = enabled
	modelTrainedMutex.Unlock()

	// Save the updated flag to Redis
	err := SaveModelTrainedFlagToRedis(ctx)
	if err != nil {
		return enabled, err
	}

	// Publish learning mode update notification to other instances
	pubErr := PublishLearningModeUpdate(ctx, enabled)
	if pubErr != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to publish learning mode update notification: %v", pubErr),
		)
		// We don't return the error here because the learning mode was successfully updated locally
		// and in Redis, even if the notification failed
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "set_learning_mode",
		"learning_mode", enabled,
	)

	return enabled, nil
}

// GetLearningMode determines if the system is in learning mode, based on training status and dry-run configuration.
func GetLearningMode() bool {
	modelTrainedMutex.RLock()
	enabled := !modelTrained || modelDryRun
	modelTrainedMutex.RUnlock()

	// Also check if dry run is enabled in the configuration
	return enabled || config.GetFile().GetBruteForce().GetNeuralNetwork().GetDryRun()
}

// getLearningModeUpdateChannel returns a common channel name for learning mode updates
// This channel is shared across all instances to ensure learning mode updates are propagated to all instances
func getLearningModeUpdateChannel() string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:common:learning_mode:updates"
}
