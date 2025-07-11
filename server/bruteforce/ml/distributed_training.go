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
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"

	"github.com/go-kit/log/level"
	"github.com/redis/go-redis/v9"
)

// PublishModelUpdate publishes a message to notify other instances that a new model is available.
// This function is part of the distributed model training system that enables multiple instances
// of Nauthilus to share neural network models. When one instance trains a model (either through
// scheduled training or after collecting enough feedback), it saves the model to Redis and then
// calls this function to notify other instances that a new model is available.
//
// The function publishes a message to a Redis channel that includes:
// - The timestamp of when the model was updated
// - The name of the instance that trained the model
//
// Other instances subscribe to this channel and reload the model when they receive a notification.
// This ensures that all instances use the most up-to-date model without having to train it themselves.
//
// Parameters:
// - ctx: The context for the request
//
// Returns an error if the message could not be published.
func PublishModelUpdate(ctx context.Context) error {
	// Get Redis client
	redisClient := rediscli.GetClient().GetWriteHandle()
	if redisClient == nil {
		return fmt.Errorf("failed to get Redis client for publishing model update")
	}

	// Create message with timestamp and instance name
	timestamp := time.Now().Unix()
	message := map[string]any{
		"timestamp":     timestamp,
		"instance_name": config.GetFile().GetServer().GetInstanceName(),
	}

	// Convert message to JSON
	jsonBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal model update message: %w", err)
	}

	// Publish message to channel
	channel := getModelUpdateChannel()
	err = redisClient.Publish(ctx, channel, jsonBytes).Err()
	if err != nil {
		return fmt.Errorf("failed to publish model update message: %w", err)
	}

	// Store the notification in Redis for persistence
	// This ensures instances that are down when the notification is published
	// can still retrieve it when they come back up
	storeKey := getModelUpdateStoreKey()
	err = redisClient.ZAdd(ctx, storeKey, redis.Z{
		Score:  float64(timestamp),
		Member: string(jsonBytes),
	}).Err()
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to store model update notification in Redis: %v", err),
		)
		// Continue despite error - the pub/sub notification will still work for online instances
	} else {
		// Trim the sorted set to keep only the last 10 notifications
		// This prevents the set from growing indefinitely
		err = redisClient.ZRemRangeByRank(ctx, storeKey, 0, -11).Err()
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to trim model update notification store: %v", err),
			)
			// Continue despite error - this is just housekeeping
		}

		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Stored model update notification in Redis for persistence",
			"store_key", storeKey,
			"timestamp", time.Unix(timestamp, 0).Format(time.RFC3339),
		)
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Published model update notification",
		"channel", channel,
	)

	return nil
}

// AcquireTrainingLock attempts to acquire a distributed lock for model training.
// This prevents multiple instances from training simultaneously.
// Returns true if the lock was acquired, false otherwise.
// The lock automatically expires after the specified duration to prevent deadlocks.
//
// This function is part of the distributed training coordination system that ensures:
// 1. Only one instance trains at a time (using Redis-based distributed locking)
// 2. Training doesn't happen too frequently (using timestamp tracking)
// 3. All instances benefit from training (using the pub/sub notification system)
//
// The system handles the following scenarios:
//   - Multiple instances trying to train simultaneously: Only one acquires the lock and trains
//   - Rolling updates with instances starting at different times: The timestamp check prevents
//     training too frequently, even if instances are restarted at different times
//   - Feedback-triggered training: Uses the same locking mechanism but with a shorter minimum
//     interval between trainings due to the higher value of feedback data
func AcquireTrainingLock(ctx context.Context, duration time.Duration) (bool, error) {
	// Get Redis client
	redisClient := rediscli.GetClient().GetWriteHandle()
	if redisClient == nil {
		return false, fmt.Errorf("failed to get Redis client for training lock")
	}

	// Generate a unique lock value (instance name + timestamp + random number for uniqueness)
	instanceName := config.GetFile().GetServer().GetInstanceName()
	lockValue := instanceName + ":" + strconv.FormatInt(time.Now().UnixNano(), 10) + ":" + strconv.FormatInt(rand.Int63(), 10)

	// Try to set the key only if it doesn't exist (NX) with an expiration (EX)
	// Use the global prefix for cluster-wide locking
	key := getMLGlobalKeyPrefix() + "training:lock"
	success, err := redisClient.SetNX(ctx, key, lockValue, duration).Result()

	if err != nil {
		return false, fmt.Errorf("failed to acquire training lock: %w", err)
	}

	if success {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Acquired distributed training lock",
			"token", lockValue,
			"expires_in", duration.String(),
		)
	} else {
		// Get the current lock holder for logging
		currentHolder, err := redisClient.Get(ctx, key).Result()
		if err == nil {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Could not acquire training lock, already held by another instance",
				"current_holder", currentHolder,
			)
		}
	}

	return success, nil
}

// ExtendTrainingLock extends the TTL of the distributed lock for model training.
// This should be called periodically during long-running training operations to prevent
// the lock from expiring before training is complete.
// It only extends the lock if the current instance is the lock holder.
//
// Returns true if the lock was extended, false otherwise.
func ExtendTrainingLock(ctx context.Context, duration time.Duration) (bool, error) {
	// Get Redis client
	redisClient := rediscli.GetClient().GetWriteHandle()
	if redisClient == nil {
		return false, fmt.Errorf("failed to get Redis client for extending training lock")
	}

	// Get the current lock holder
	key := getMLGlobalKeyPrefix() + "training:lock"
	currentHolder, err := redisClient.Get(ctx, key).Result()

	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Lock doesn't exist, nothing to extend
			return false, nil
		}

		return false, fmt.Errorf("failed to get current lock holder: %w", err)
	}

	// Check if the current instance is the lock holder
	// We check if the lock value starts with our instance name
	instanceName := config.GetFile().GetServer().GetInstanceName()
	if strings.HasPrefix(currentHolder, instanceName+":") {
		// Extend the lock using a Lua script for atomic check-and-extend
		// This ensures we only extend the lock if it still has our value
		script := `
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("EXPIRE", KEYS[1], ARGV[2])
		else
			return 0
		end
		`

		// Execute the script
		result, err := redisClient.Eval(ctx, script, []string{key}, currentHolder, int(duration.Seconds())).Result()
		if err != nil {
			return false, fmt.Errorf("failed to execute lock extension script: %w", err)
		}

		// Check if the lock was extended
		if result.(int64) == 1 {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Extended distributed training lock",
				"token", currentHolder,
				"duration", duration.String(),
			)

			return true, nil
		} else {
			level.Warn(log.Logger).Log(
				definitions.LogKeyMsg, "Failed to extend distributed training lock - value changed",
				"expected_token", currentHolder,
			)

			return false, nil
		}
	} else {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Not extending training lock - owned by different instance",
			"current_holder", currentHolder,
		)

		return false, nil
	}
}

// ReleaseTrainingLock releases the distributed lock for model training.
// This should be called after training is complete or if training fails.
// It only releases the lock if the current instance is the lock holder.
//
// This function is part of the distributed training coordination system that ensures
// only one instance trains at a time. After an instance completes training (or if training
// fails), it releases the lock to allow other instances to acquire it if needed.
//
// The lock is instance-specific, meaning only the instance that acquired the lock can
// release it. This prevents one instance from accidentally releasing another instance's lock.
// Additionally, the lock has an automatic expiration time to prevent deadlocks in case
// an instance crashes or is terminated before it can release the lock.
func ReleaseTrainingLock(ctx context.Context) error {
	// Get Redis client
	redisClient := rediscli.GetClient().GetWriteHandle()
	if redisClient == nil {
		return fmt.Errorf("failed to get Redis client for releasing training lock")
	}

	// Get the current lock holder
	key := getMLGlobalKeyPrefix() + "training:lock"
	currentHolder, err := redisClient.Get(ctx, key).Result()

	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Lock doesn't exist, nothing to release
			return nil
		}

		return fmt.Errorf("failed to get current lock holder: %w", err)
	}

	// Check if the current instance is the lock holder
	// We check if the lock value starts with our instance name
	instanceName := config.GetFile().GetServer().GetInstanceName()
	if strings.HasPrefix(currentHolder, instanceName+":") {
		// Release the lock using a Lua script for atomic check-and-delete
		// This ensures we only delete the lock if it still has our value
		script := `
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("DEL", KEYS[1])
		else
			return 0
		end
		`

		// Execute the script
		result, err := redisClient.Eval(ctx, script, []string{key}, currentHolder).Result()
		if err != nil {
			return fmt.Errorf("failed to execute lock release script: %w", err)
		}

		// Check if the lock was released
		if result.(int64) == 1 {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Released distributed training lock",
				"token", currentHolder,
			)
		} else {
			level.Warn(log.Logger).Log(
				definitions.LogKeyMsg, "Failed to release distributed training lock - value changed",
				"expected_token", currentHolder,
			)
		}
	} else {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Not releasing training lock - owned by different instance",
			"current_holder", currentHolder,
		)
	}

	return nil
}

// GetLastTrainingTime retrieves the timestamp of the last successful model training.
// Returns the timestamp and nil if successful, or zero time and an error if unsuccessful.
//
// This function is part of the distributed training coordination system that prevents
// training from happening too frequently, especially during rolling updates where
// instances are restarted at different times. By tracking when the last successful
// training occurred (across all instances), the system can make intelligent decisions
// about whether to initiate a new training cycle.
//
// The timestamp is stored in Redis and shared across all instances, ensuring that
// even if instances are started at different times (e.g., during a rolling update),
// they all have access to the same information about when training last occurred.
func GetLastTrainingTime(ctx context.Context) (time.Time, error) {
	// Get Redis client
	redisClient := rediscli.GetClient().GetReadHandle()
	if redisClient == nil {
		return time.Time{}, fmt.Errorf("failed to get Redis client for last training time")
	}

	// Get the last training timestamp using the global prefix
	key := getMLGlobalKeyPrefix() + "last:training:time"
	timestampStr, err := redisClient.Get(ctx, key).Result()

	if err != nil {
		if errors.Is(err, redis.Nil) {
			// No last training time recorded yet
			return time.Time{}, nil
		}

		return time.Time{}, fmt.Errorf("failed to get last training time: %w", err)
	}

	// Parse the timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse last training timestamp: %w", err)
	}

	return time.Unix(timestamp, 0), nil
}

// SetLastTrainingTime records the timestamp of the last successful model training.
//
// This function is called after a successful training operation to update the shared
// timestamp in Redis. This timestamp is used by all instances to determine when the
// last training occurred, regardless of which instance performed the training.
//
// By maintaining this timestamp, the system ensures that:
//  1. Training doesn't happen too frequently, which could waste resources
//  2. During rolling updates, new instances don't immediately start training
//     if another instance recently completed training
//  3. Different training triggers (scheduled vs. feedback-triggered) can
//     coordinate with each other to prevent unnecessary training
//
// This function also increments a counter to track the number of training cycles
// in a short period of time, which is used to detect and break potential training loops.
func SetLastTrainingTime(ctx context.Context) error {
	// Get Redis client
	redisClient := rediscli.GetClient().GetWriteHandle()
	if redisClient == nil {
		return fmt.Errorf("failed to get Redis client for setting last training time")
	}

	// Set the current time as the last training timestamp using the global prefix
	key := getMLGlobalKeyPrefix() + "last:training:time"
	timestamp := time.Now().Unix()

	if err := redisClient.Set(ctx, key, strconv.FormatInt(timestamp, 10), 0).Err(); err != nil {
		return fmt.Errorf("failed to set last training time: %w", err)
	}

	// Increment the training counter and set expiration to 24 hours
	// This counter is used to detect training loops
	// Use the global prefix for cluster-wide loop detection
	counterKey := getMLGlobalKeyPrefix() + "training:counter"
	count, err := redisClient.Incr(ctx, counterKey).Result()
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to increment training counter: %v", err),
		)
		// Continue despite error - this is just for loop detection
	} else {
		// Set expiration on the counter if it doesn't exist
		redisClient.Expire(ctx, counterKey, 24*time.Hour)

		// If there have been too many training cycles in a short period, log a warning
		if count > 5 {
			level.Warn(log.Logger).Log(
				definitions.LogKeyMsg, "Potential training loop detected - too many training cycles in a short period",
				"count", count,
				"period", "24 hours",
			)

			// Force a longer cooldown by setting the timestamp further in the future
			// This effectively creates a 24-hour cooldown from now
			futureTimestamp := time.Now().Add(24 * time.Hour).Unix()
			if err := redisClient.Set(ctx, key, strconv.FormatInt(futureTimestamp, 10), 0).Err(); err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to set extended cooldown period: %v", err),
				)
			} else {
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, "Enforced extended cooldown period to break potential training loop",
					"cooldown", "24 hours",
					"timestamp", time.Unix(futureTimestamp, 0).Format(time.RFC3339),
				)
			}
		}
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Updated last training timestamp",
		"timestamp", time.Unix(timestamp, 0).Format(time.RFC3339),
	)

	return nil
}

// modelUpdateSubscriber listens for model update notifications and triggers model reload when updates are received.
// It subscribes to a Redis pub/sub channel for update events and processes incoming messages.
// The function ensures updates from the current instance are skipped to prevent redundant reloads.
// It gracefully handles termination via context cancellation or stop channel signals.
func modelUpdateSubscriber(ctx context.Context, stopChan chan struct{}) {
	redisClient := rediscli.GetClient().GetReadHandle()
	if redisClient == nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, "Failed to get Redis client for model update subscription",
		)

		return
	}

	// Subscribe to model update channel
	channel := getModelUpdateChannel()
	pubsub := redisClient.Subscribe(ctx, channel)

	defer pubsub.Close()

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Subscribed to model update notifications",
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
					definitions.LogKeyMsg, fmt.Sprintf("Failed to parse model update message: %v", err),
					"payload", msg.Payload,
				)

				continue
			}

			// Skip our own messages
			if instanceName, ok := updateMsg["instance_name"].(string); ok {
				if instanceName == config.GetFile().GetServer().GetInstanceName() {
					util.DebugModule(definitions.DbgNeural,
						"action", "skip_own_model_update",
					)

					continue
				}
			}

			// Check if the update timestamp is newer than our last training time
			// This prevents loading older models and potentially triggering unnecessary retraining
			if timestamp, ok := updateMsg["timestamp"].(float64); ok {
				updateTime := time.Unix(int64(timestamp), 0)
				lastTrainingTime, err := GetLastTrainingTime(ctx)
				if err == nil && !lastTrainingTime.IsZero() {
					// If our last training is more recent than the update, skip it
					if lastTrainingTime.After(updateTime) {
						util.DebugModule(definitions.DbgNeural,
							"action", "skip_older_model_update",
							"update_time", updateTime.Format(time.RFC3339),
							"last_training_time", lastTrainingTime.Format(time.RFC3339),
						)

						level.Info(log.Logger).Log(
							definitions.LogKeyMsg, "Skipping model update - our model is more recent",
							"update_time", updateTime.Format(time.RFC3339),
							"our_time", lastTrainingTime.Format(time.RFC3339),
						)

						continue
					}
				}
			}

			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Received model update notification, reloading model",
				"from_instance", updateMsg["instance_name"],
			)

			// Reload model
			globalTrainerMutex.RLock()
			localTrainer := globalTrainer
			globalTrainerMutex.RUnlock()

			if localTrainer != nil {
				// Get the canonical list of features from Redis
				canonicalFeatures, err := GetDynamicFeaturesFromRedis(ctx)
				if err != nil {
					level.Warn(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Failed to retrieve canonical feature list from Redis during model update: %v", err),
					)
				} else if len(canonicalFeatures) > 0 {
					level.Info(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Loaded canonical feature list with %d features during model update", len(canonicalFeatures)),
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
							definitions.LogKeyMsg, fmt.Sprintf("Added %d missing features from canonical list during model update", len(addedFeatures)),
							"features", strings.Join(addedFeatures, ", "),
						)
					}

					// Log detailed information about removed features
					if len(removedFeatures) > 0 {
						level.Info(log.Logger).Log(
							definitions.LogKeyMsg, fmt.Sprintf("Removed %d features that are no longer in canonical list during model update", len(removedFeatures)),
							"features", strings.Join(removedFeatures, ", "),
						)
					}

					util.DebugModule(definitions.DbgNeural,
						"action", "update_canonical_features_during_model_update",
						"features_added", len(addedFeatures),
						"features_removed", len(removedFeatures),
						"total_features", len(existingFeatures),
					)
				}

				// Ensure the trainer has the current context before loading the model
				localTrainer = localTrainer.WithContext(ctx)

				// Reset the model to use the canonical features from Redis
				if resetErr := ResetModelToCanonicalFeatures(ctx); resetErr != nil {
					level.Error(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Failed to reset model to canonical features during model update: %v", resetErr),
					)
					// Continue despite error - we'll still try to load the model
				} else {
					level.Info(log.Logger).Log(
						definitions.LogKeyMsg, "Successfully reset model to canonical features during model update",
					)
				}

				if loadErr := localTrainer.LoadModelFromRedis(); loadErr != nil {
					level.Error(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Failed to reload model after update notification: %v", loadErr),
					)
				} else {
					level.Info(log.Logger).Log(
						definitions.LogKeyMsg, "Successfully reloaded model after update notification",
					)

					// Also update the model trained flags from Redis
					if err := LoadModelTrainedFlagFromRedis(ctx); err != nil {
						level.Error(log.Logger).Log(
							definitions.LogKeyMsg, fmt.Sprintf("Failed to load model trained flags from Redis after update notification: %v", err),
						)
					}

					// Update the last training time to prevent immediate retraining
					// This is crucial to prevent a training loop between instances
					if err := SetLastTrainingTime(ctx); err != nil {
						level.Error(log.Logger).Log(
							definitions.LogKeyMsg, fmt.Sprintf("Failed to update last training time after model update: %v", err),
						)
					} else {
						level.Info(log.Logger).Log(
							definitions.LogKeyMsg, "Updated last training time after model update to prevent retraining loop",
						)
					}

					// Update the global trainer with the updated trainer
					globalTrainerMutex.Lock()
					globalTrainer = localTrainer
					globalTrainerMutex.Unlock()
				}
			}
		}
	}
}

// scheduledTraining periodically trains the model
func scheduledTraining(ctx context.Context, stopChan chan struct{}) {
	ticker := time.NewTicker(12 * time.Hour) // Train once twice per day
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopChan:
			return
		case <-ticker.C:
			performScheduledTraining(ctx)
		}
	}
}

// performScheduledTraining manages the periodic training of a machine learning model in a distributed environment.
// It prevents over-training, ensures synchronization across instances, and utilizes locks to avoid concurrent training.
func performScheduledTraining(ctx context.Context) {
	// Check when the last training occurred
	lastTrainingTime, err := GetLastTrainingTime(ctx)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to get last training time: %v", err),
		)
		// Skip training if we can't determine the last training time
		// This prevents training loops during system restarts or Redis connectivity issues
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Skipping scheduled training - cannot determine last training time",
		)

		return
	} else if !lastTrainingTime.IsZero() {
		// If last training was less than 12 hours ago, skip this training cycle
		// This prevents training too frequently, especially during rolling updates
		minInterval := 12 * time.Hour
		timeSinceLastTraining := time.Since(lastTrainingTime)

		if timeSinceLastTraining < minInterval {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, "Skipping scheduled training - too soon since last training",
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

	// Try to acquire the distributed training lock
	// Use a reasonable timeout to prevent deadlocks (30 minutes should be enough for training)
	lockAcquired, lockErr := AcquireTrainingLock(ctx, 30*time.Minute)
	if lockErr != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to acquire training lock: %v", lockErr),
		)

		return
	}

	if !lockAcquired {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Skipping scheduled training - another instance is already training",
		)

		return
	}

	// We have the lock, proceed with training
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Starting scheduled model training",
	)

	// Start a goroutine to periodically extend the lock TTL during training
	// This prevents the lock from expiring if training takes longer than expected
	heartbeatCtx, heartbeatCancel := context.WithCancel(ctx)
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

	// Acquire write lock before training
	globalTrainerMutex.RLock()
	localTrainer := globalTrainer
	globalTrainerMutex.RUnlock()

	// Train with the last 5000 samples for 50 epochs
	trainErr := localTrainer.TrainWithStoredData(5000, 50)

	// Stop the heartbeat goroutine
	heartbeatCancel()
	<-heartbeatDone // Wait for the heartbeat goroutine to finish

	if trainErr != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Scheduled training failed: %v", trainErr),
		)

		// Release the lock since training failed
		if releaseErr := ReleaseTrainingLock(ctx); releaseErr != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to release training lock: %v", releaseErr),
			)
		}

		return
	}

	// Save the trained model to Redis
	saveErr := localTrainer.SaveModelToRedis()
	if saveErr != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to save model to Redis: %v", saveErr),
		)

		// Release the lock since saving failed
		if releaseErr := ReleaseTrainingLock(ctx); releaseErr != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to release training lock: %v", releaseErr),
			)
		}

		return
	}

	// Update the last training timestamp
	if timeErr := SetLastTrainingTime(ctx); timeErr != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to update last training time: %v", timeErr),
		)
		// Continue despite error - this just means next training might happen sooner than optimal
	}

	// Publish model update notification to other instances
	pubErr := PublishModelUpdate(ctx)
	if pubErr != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to publish model update notification: %v", pubErr),
		)
		// Continue despite error - other instances will still work, just won't get the update notification
	}

	// Release the training lock
	if releaseErr := ReleaseTrainingLock(ctx); releaseErr != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to release training lock: %v", releaseErr),
		)
	}
}

// getModelUpdateChannel returns a common channel name for model updates
// This channel is shared across all instances to ensure model updates are propagated to all instances
func getModelUpdateChannel() string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:common:model:updates"
}

// checkForMissedModelUpdates checks for model update notifications that were published
// while the instance was down and processes them.
// This function is called during initialization to ensure that instances that were down
// when notifications were published can still process them when they come back up.
func checkForMissedModelUpdates(ctx context.Context, trainer *NeuralNetworkTrainer) {
	// Get Redis client
	redisClient := rediscli.GetClient().GetReadHandle()
	if redisClient == nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, "Failed to get Redis client for checking missed model updates",
		)

		return
	}

	// Get the last training time
	lastTrainingTime, err := GetLastTrainingTime(ctx)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to get last training time during missed update check: %v", err),
		)

		// Continue with a zero time, which will process all notifications
		lastTrainingTime = time.Time{}
	}

	// Get the key for the notification store
	storeKey := getModelUpdateStoreKey()

	// Get all notifications from the store that are newer than our last training time
	// If lastTrainingTime is zero, this will get all notifications
	var minScore string
	if lastTrainingTime.IsZero() {
		minScore = "-inf"
	} else {
		minScore = strconv.FormatInt(lastTrainingTime.Unix(), 10)
	}

	// Get notifications with scores greater than our last training time
	notifications, err := redisClient.ZRangeByScore(ctx, storeKey, &redis.ZRangeBy{
		Min: minScore,
		Max: "+inf",
	}).Result()

	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to get missed model update notifications: %v", err),
		)

		return
	}

	if len(notifications) == 0 {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "No missed model update notifications found",
		)

		return
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Found %d missed model update notifications", len(notifications)),
	)

	// Process each notification
	for _, notificationJSON := range notifications {
		// Parse the notification
		var notification map[string]any
		if err := json.Unmarshal([]byte(notificationJSON), &notification); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to parse missed model update notification: %v", err),
				"notification", notificationJSON,
			)

			continue
		}

		// Skip our own notifications
		if instanceName, ok := notification["instance_name"].(string); ok {
			if instanceName == config.GetFile().GetServer().GetInstanceName() {
				util.DebugModule(definitions.DbgNeural,
					"action", "skip_own_missed_model_update",
				)

				continue
			}
		}

		// Check if the update timestamp is newer than our last training time
		if timestamp, ok := notification["timestamp"].(float64); ok {
			updateTime := time.Unix(int64(timestamp), 0)
			if !lastTrainingTime.IsZero() && lastTrainingTime.After(updateTime) {
				util.DebugModule(definitions.DbgNeural,
					"action", "skip_older_missed_model_update",
					"update_time", updateTime.Format(time.RFC3339),
					"last_training_time", lastTrainingTime.Format(time.RFC3339),
				)

				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, "Skipping missed model update - our model is more recent",
					"update_time", updateTime.Format(time.RFC3339),
					"our_time", lastTrainingTime.Format(time.RFC3339),
				)

				continue
			}
		}

		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Processing missed model update notification",
			"from_instance", notification["instance_name"],
		)

		// Process the notification by reloading the model
		// This is similar to what modelUpdateSubscriber does
		if trainer != nil {
			// Get the canonical list of features from Redis
			canonicalFeatures, err := GetDynamicFeaturesFromRedis(ctx)
			if err != nil {
				level.Warn(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to retrieve canonical feature list from Redis during missed update processing: %v", err),
				)
			} else if len(canonicalFeatures) > 0 {
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Loaded canonical feature list with %d features during missed update processing", len(canonicalFeatures)),
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
						definitions.LogKeyMsg, fmt.Sprintf("Added %d missing features from canonical list during missed update processing", len(addedFeatures)),
						"features", strings.Join(addedFeatures, ", "),
					)
				}

				// Log detailed information about removed features
				if len(removedFeatures) > 0 {
					level.Info(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Removed %d features that are no longer in canonical list during missed update processing", len(removedFeatures)),
						"features", strings.Join(removedFeatures, ", "),
					)
				}

				util.DebugModule(definitions.DbgNeural,
					"action", "update_canonical_features_during_missed_update_processing",
					"features_added", len(addedFeatures),
					"features_removed", len(removedFeatures),
					"total_features", len(existingFeatures),
				)
			}

			// Ensure the trainer has the current context before loading the model
			trainer = trainer.WithContext(ctx)

			// Reset the model to use the canonical features from Redis
			if resetErr := ResetModelToCanonicalFeatures(ctx); resetErr != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to reset model to canonical features during missed update processing: %v", resetErr),
				)
				// Continue despite error - we'll still try to load the model
			}

			// Load the model from Redis
			if loadErr := trainer.LoadModelFromRedis(); loadErr != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to load model from Redis during missed update processing: %v", loadErr),
				)
			} else {
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, "Successfully loaded model from Redis during missed update processing",
				)

				// Update the last training time to prevent immediate retraining
				// This is crucial to prevent a training loop between instances
				if err := SetLastTrainingTime(ctx); err != nil {
					level.Error(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Failed to update last training time after missed update processing: %v", err),
					)
				} else {
					level.Info(log.Logger).Log(
						definitions.LogKeyMsg, "Updated last training time after missed update processing to prevent retraining loop",
					)
				}

				// Update the global trainer with the updated trainer
				globalTrainerMutex.Lock()
				globalTrainer = trainer
				globalTrainerMutex.Unlock()
			}
		}
	}
}
