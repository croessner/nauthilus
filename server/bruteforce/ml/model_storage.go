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
	"github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
)

// getMLGlobalKeyPrefix returns the Redis key prefix for global ML operations
// This prefix is shared across all instances for cluster-wide coordination
const mlGlobalPrefix = "ml:global:"

// getMLGlobalKeyPrefix constructs and returns the global key prefix used for machine learning-related Redis entries.
func getMLGlobalKeyPrefix() string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + mlGlobalPrefix
}

// getModelUpdateStoreKey constructs and returns the Redis store key for model update data using the configured prefix.
func getModelUpdateStoreKey() string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:common:model:updates:store"
}

// getModelTrainedRedisKey returns the Redis key for the model trained flag
func getModelTrainedRedisKey() string {
	return getMLGlobalKeyPrefix() + "MODEL_TRAINED"
}

// LoadModelFromRedis loads a previously trained model from Redis
func (t *NeuralNetworkTrainer) LoadModelFromRedis() error {
	return t.LoadModelFromRedisWithKey(getMLGlobalKeyPrefix() + "model")
}

// LoadModelFromRedisWithKey loads a previously trained model from Redis using the specified key
func (t *NeuralNetworkTrainer) LoadModelFromRedisWithKey(key string) error {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	// Get the model data from Redis
	jsonData, err := rediscli.GetClient().GetReadHandle().Get(t.ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return fmt.Errorf("no saved model found for key %s", key)
		}

		return fmt.Errorf("failed to retrieve model from Redis for key %s: %w", key, err)
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "load_model_data_received",
		"key", key,
		"data_size", len(jsonData),
	)

	// Parse the JSON data
	var modelData struct {
		InputSize          int       `json:"input_size"`
		HiddenSize         int       `json:"hidden_size"`
		OutputSize         int       `json:"output_size"`
		Weights            []float64 `json:"weights"`
		HiddenBias         []float64 `json:"hidden_bias"`
		OutputBias         []float64 `json:"output_bias"`
		LearningRate       float64   `json:"learning_rate"`
		ActivationFunction string    `json:"activation_function"`
	}

	// Use jsoniter without decimal truncation for ML package
	var json = jsoniter.Config{
		EscapeHTML:                    true,
		SortMapKeys:                   true,
		ValidateJsonRawMessage:        true,
		MarshalFloatWith6Digits:       false,
		ObjectFieldMustBeSimpleString: true,
	}.Froze()

	if err := json.Unmarshal(jsonData, &modelData); err != nil {
		return fmt.Errorf("failed to deserialize model: %w", err)
	}

	// Get activation function from config or use default if not in the model data
	activationFunction := modelData.ActivationFunction
	if activationFunction == "" {
		// For backward compatibility with models saved before this change
		nnConfig := config.GetFile().GetBruteForce().GetNeuralNetwork()
		if nnConfig != nil {
			activationFunction = nnConfig.ActivationFunction
		}

		if activationFunction == "" {
			activationFunction = "sigmoid" // Default to sigmoid if not specified
		}
	}

	// Check if we need to adjust the input size for additional features from Lua context
	originalInputSize := modelData.InputSize
	inputSize := originalInputSize

	// Track which features we need to add
	var newFeatures []string

	// Flag to track if input size was adjusted
	inputSizeAdjusted := false

	// Skip dynamic neuron adjustment during tests
	if os.Getenv("NAUTHILUS_TESTING") != "1" {
		// First, get the canonical list of dynamic features from Redis
		canonicalFeatures, err := GetDynamicFeaturesFromRedis(t.ctx)
		if err != nil {
			level.Warn(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to retrieve canonical feature list from Redis: %v", err),
			)

			// Continue with empty list if there was an error
			canonicalFeatures = []string{}
		}

		// Check if we have additional features from Lua context that weren't in the model
		var contextFeatures []string
		if t.ctx != nil {
			if additionalFeatures, ok := t.ctx.Value(definitions.CtxAdditionalFeaturesKey).(map[string]any); ok && len(additionalFeatures) > 0 {
				// Track all feature names from context
				for featureName := range additionalFeatures {
					contextFeatures = append(contextFeatures, featureName)
				}
			}
		}

		// Combine canonical features with context features to get a complete list
		allFeatures := make(map[string]bool)

		// Add canonical features
		for _, feature := range canonicalFeatures {
			allFeatures[feature] = true
		}

		// Add context features
		for _, feature := range contextFeatures {
			allFeatures[feature] = true
		}

		// Convert back to slice for processing
		var combinedFeatures []string
		for feature := range allFeatures {
			combinedFeatures = append(combinedFeatures, feature)
		}

		// Get a sample of training data to check what features were already in the model
		trainingData, trainingErr := t.GetTrainingDataFromRedis(1)

		// Determine which features are new and need to be added to the model
		for _, featureName := range combinedFeatures {
			isNewFeature := false

			if trainingErr != nil || len(trainingData) == 0 || trainingData[0].Features == nil ||
				trainingData[0].Features.AdditionalFeatures == nil {
				// No training data features, all combined features are new
				isNewFeature = true
			} else {
				// Check if this feature exists in training data
				if _, exists := trainingData[0].Features.AdditionalFeatures[featureName]; !exists {
					isNewFeature = true
				}
			}

			// If this is a new feature, add it to the model
			if isNewFeature {
				inputSize++
				inputSizeAdjusted = true
				newFeatures = append(newFeatures, featureName)

				util.DebugModule(definitions.DbgNeural,
					"action", "adjust_model_input_size_with_feature",
					"feature_name", featureName,
					"original_input_size", originalInputSize,
					"current_input_size", inputSize,
				)
			}
		}

		// Store the updated list of features to Redis
		if len(newFeatures) > 0 {
			if storeErr := StoreDynamicFeaturesToRedis(t.ctx, combinedFeatures); storeErr != nil {
				level.Warn(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to store updated feature list to Redis: %v", storeErr),
				)
			} else {
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Updated canonical feature list in Redis with %d features", len(combinedFeatures)),
				)
			}
		}

		// Log if we adjusted the input size
		if inputSizeAdjusted {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Adjusted model input size from %d to %d to account for dynamic neurons: %s",
					originalInputSize, inputSize, strings.Join(newFeatures, ", ")),
			)

			// Update the input size in the model data
			modelData.InputSize = inputSize
		}
	} else {
		util.DebugModule(definitions.DbgNeural,
			"action", "skip_dynamic_neuron_adjustment",
			"reason", "running_in_test_environment",
			"input_size", inputSize,
		)
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "load_model_parsed",
		"key", key,
		"input_size", modelData.InputSize,
		"hidden_size", modelData.HiddenSize,
		"output_size", modelData.OutputSize,
		"weights_count", len(modelData.Weights),
		"hidden_bias_count", len(modelData.HiddenBias),
		"output_bias_count", len(modelData.OutputBias),
		"activation_function", activationFunction,
	)

	// Check if we need to resize the weights array due to input size adjustment
	expectedWeightsSize := modelData.InputSize*modelData.HiddenSize + modelData.HiddenSize*modelData.OutputSize
	originalWeightsSize := len(modelData.Weights)

	// Skip weights array resizing during tests
	if os.Getenv("NAUTHILUS_TESTING") != "1" && originalWeightsSize != expectedWeightsSize {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Resizing weights array from %d to %d elements due to input size adjustment",
				originalWeightsSize, expectedWeightsSize),
		)

		// Create a new weights array with the correct size
		newWeights := make([]float64, expectedWeightsSize)

		// If the input size increased, we need to preserve the existing weights and initialize the new ones
		if originalInputSize < modelData.InputSize {
			// Calculate how many new input neurons we have
			newInputNeurons := modelData.InputSize - originalInputSize

			// Copy weights for existing input-to-hidden connections
			// For each hidden neuron, copy its connections from the original inputs
			for h := 0; h < modelData.HiddenSize; h++ {
				for i := 0; i < originalInputSize; i++ {
					oldIndex := h*originalInputSize + i
					newIndex := h*modelData.InputSize + i

					if oldIndex < originalWeightsSize {
						newWeights[newIndex] = modelData.Weights[oldIndex]
					}
				}

				// Initialize weights for new input neurons with small random values
				for i := 0; i < newInputNeurons; i++ {
					newIndex := h*modelData.InputSize + originalInputSize + i
					newWeights[newIndex] = (rand.Float64() - 0.5) * 0.1
				}
			}

			// Copy weights for hidden-to-output connections
			// These connections start after all input-to-hidden connections
			hiddenToOutputStart := modelData.InputSize * modelData.HiddenSize
			oldHiddenToOutputStart := originalInputSize * modelData.HiddenSize

			for o := 0; o < modelData.OutputSize; o++ {
				for h := 0; h < modelData.HiddenSize; h++ {
					oldIndex := oldHiddenToOutputStart + o*modelData.HiddenSize + h
					newIndex := hiddenToOutputStart + o*modelData.HiddenSize + h

					if oldIndex < originalWeightsSize {
						newWeights[newIndex] = modelData.Weights[oldIndex]
					}
				}
			}

			util.DebugModule(definitions.DbgNeural,
				"action", "resize_weights_array",
				"reason", "input_size_increased",
				"original_input_size", originalInputSize,
				"new_input_size", modelData.InputSize,
				"new_input_neurons", newInputNeurons,
				"original_weights_size", originalWeightsSize,
				"new_weights_size", expectedWeightsSize,
			)
		} else {
			// If the input size decreased (unlikely but possible), initialize all weights
			for i := range newWeights {
				newWeights[i] = (rand.Float64() - 0.5) * 0.1
			}

			util.DebugModule(definitions.DbgNeural,
				"action", "resize_weights_array",
				"reason", "input_size_changed_unexpectedly",
				"original_input_size", originalInputSize,
				"new_input_size", modelData.InputSize,
				"original_weights_size", originalWeightsSize,
				"new_weights_size", expectedWeightsSize,
			)
		}

		// Update the weights in the model data
		modelData.Weights = newWeights
	} else if os.Getenv("NAUTHILUS_TESTING") == "1" && originalWeightsSize != expectedWeightsSize {
		util.DebugModule(definitions.DbgNeural,
			"action", "skip_weights_array_resizing",
			"reason", "running_in_test_environment",
			"original_weights_size", originalWeightsSize,
			"expected_weights_size", expectedWeightsSize,
		)
	}

	// Create a new neural network with the loaded parameters
	nn := &NeuralNetwork{
		inputSize:          modelData.InputSize,
		hiddenSize:         modelData.HiddenSize,
		outputSize:         modelData.OutputSize,
		weights:            modelData.Weights,
		hiddenBias:         modelData.HiddenBias,
		outputBias:         modelData.OutputBias,
		learningRate:       modelData.LearningRate,
		activationFunction: activationFunction,
		rng:                rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	// Initialize bias terms if they're not present in the loaded model (backward compatibility)
	if len(nn.hiddenBias) != nn.hiddenSize {
		util.DebugModule(definitions.DbgNeural,
			"action", "initialize_missing_hidden_bias",
			"reason", "backward_compatibility",
			"expected_size", nn.hiddenSize,
			"actual_size", len(nn.hiddenBias),
		)

		nn.hiddenBias = make([]float64, nn.hiddenSize)
		// Initialize with small random values
		for i := range nn.hiddenBias {
			nn.hiddenBias[i] = (nn.rng.Float64() - 0.5) * 0.1
		}
	}

	if len(nn.outputBias) != nn.outputSize {
		util.DebugModule(definitions.DbgNeural,
			"action", "initialize_missing_output_bias",
			"reason", "backward_compatibility",
			"expected_size", nn.outputSize,
			"actual_size", len(nn.outputBias),
		)

		nn.outputBias = make([]float64, nn.outputSize)
		// Initialize with small random values
		for i := range nn.outputBias {
			nn.outputBias[i] = (nn.rng.Float64() - 0.5) * 0.1
		}
	}

	// Replace the current model
	t.model = nn

	// Record network structure metrics
	GetMLMetrics().RecordNetworkStructure(nn.inputSize, nn.hiddenSize, nn.outputSize)

	// If we adjusted the input size or resized the weights array, save the adjusted model back to Redis
	// and publish an update notification to other instances
	// Skip this operation during tests
	if os.Getenv("NAUTHILUS_TESTING") != "1" && (inputSizeAdjusted || originalWeightsSize != expectedWeightsSize) {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Saving adjusted model back to Redis and notifying other instances",
		)

		// Save the adjusted model back to Redis
		go func() {
			// Create a new context with a timeout for the save operation
			saveCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Create a temporary trainer with the adjusted model
			tempTrainer := &NeuralNetworkTrainer{
				ctx:                 saveCtx,
				model:               nn,
				oneHotEncodings:     t.oneHotEncodings,
				oneHotSizes:         t.oneHotSizes,
				featureEncodingType: t.featureEncodingType,
				embeddingSize:       t.embeddingSize,
			}

			// Save the adjusted model to Redis
			if err := tempTrainer.SaveModelToRedisWithKey(key); err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to save adjusted model to Redis: %v", err),
				)
			} else {
				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, "Successfully saved adjusted model to Redis",
				)

				// Publish an update notification to other instances
				if err := PublishModelUpdate(saveCtx); err != nil {
					level.Error(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Failed to publish model update notification: %v", err),
					)
				} else {
					level.Info(log.Logger).Log(
						definitions.LogKeyMsg, "Successfully published model update notification",
					)
				}
			}
		}()
	} else if os.Getenv("NAUTHILUS_TESTING") == "1" && (inputSizeAdjusted || originalWeightsSize != expectedWeightsSize) {
		util.DebugModule(definitions.DbgNeural,
			"action", "skip_save_adjusted_model",
			"reason", "running_in_test_environment",
			"input_size_adjusted", inputSizeAdjusted,
			"weights_size_mismatch", originalWeightsSize != expectedWeightsSize,
		)
	}

	// Try to load encodings configuration if it exists
	encodingsKey := key + "_encodings"
	encodingsJSON, err := rediscli.GetClient().GetReadHandle().Get(t.ctx, encodingsKey).Bytes()

	if err == nil {
		// Deserialize the encodings
		var encodingsData struct {
			OneHotEncodings     map[string]map[string]int     `json:"one_hot_encodings"`
			OneHotSizes         map[string]int                `json:"one_hot_sizes"`
			FeatureEncodingType map[string]StringEncodingType `json:"feature_encoding_type"`
			EmbeddingSize       int                           `json:"embedding_size"`
		}

		if err := json.Unmarshal(encodingsJSON, &encodingsData); err == nil {
			// Replace the current encodings
			t.oneHotEncodings = encodingsData.OneHotEncodings
			t.oneHotSizes = encodingsData.OneHotSizes

			// Load embedding configurations if they exist
			if encodingsData.FeatureEncodingType != nil {
				t.featureEncodingType = encodingsData.FeatureEncodingType
			}

			// Load embedding size if it's valid
			if encodingsData.EmbeddingSize > 0 {
				t.embeddingSize = encodingsData.EmbeddingSize
			}

			util.DebugModule(definitions.DbgNeural,
				"action", "load_encodings_configuration",
				"key", encodingsKey,
				"one_hot_features_count", len(t.oneHotEncodings),
				"feature_encoding_types_count", len(t.featureEncodingType),
				"embedding_size", t.embeddingSize,
			)

			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Encodings configuration loaded from Redis successfully (key: %s)", encodingsKey),
			)
		} else {
			// Try to load legacy one-hot encodings format for backward compatibility
			var legacyEncodingsData struct {
				OneHotEncodings map[string]map[string]int `json:"one_hot_encodings"`
				OneHotSizes     map[string]int            `json:"one_hot_sizes"`
			}

			if err := json.Unmarshal(encodingsJSON, &legacyEncodingsData); err == nil {
				// Replace the current encodings
				t.oneHotEncodings = legacyEncodingsData.OneHotEncodings
				t.oneHotSizes = legacyEncodingsData.OneHotSizes

				util.DebugModule(definitions.DbgNeural,
					"action", "load_legacy_one_hot_encodings",
					"key", encodingsKey,
					"features_count", len(t.oneHotEncodings),
				)

				level.Info(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Legacy one-hot encodings loaded from Redis successfully (key: %s)", encodingsKey),
				)
			} else {
				level.Warn(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to deserialize encodings configuration: %v", err),
				)
			}
		}
	} else if !errors.Is(err, redis.Nil) {
		// Log warning but don't fail if encodings can't be loaded
		level.Warn(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to load encodings configuration from Redis: %v", err),
		)
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Model loaded from Redis successfully (key: %s)", key),
	)

	return nil
}

// SaveModelToRedis saves the trained neural network model to Redis
func (t *NeuralNetworkTrainer) SaveModelToRedis() error {
	return t.SaveModelToRedisWithKey(getMLGlobalKeyPrefix() + "model")
}

// SaveModelToRedisWithKey saves the trained neural network model to Redis using the specified key
func (t *NeuralNetworkTrainer) SaveModelToRedisWithKey(key string) error {
	if t.model == nil {
		return fmt.Errorf("no model to save")
	}

	// Create a serializable representation of the model
	modelData := struct {
		InputSize          int       `json:"input_size"`
		HiddenSize         int       `json:"hidden_size"`
		OutputSize         int       `json:"output_size"`
		Weights            []float64 `json:"weights"`
		HiddenBias         []float64 `json:"hidden_bias"`
		OutputBias         []float64 `json:"output_bias"`
		LearningRate       float64   `json:"learning_rate"`
		ActivationFunction string    `json:"activation_function"`
	}{
		InputSize:          t.model.inputSize,
		HiddenSize:         t.model.hiddenSize,
		OutputSize:         t.model.outputSize,
		Weights:            t.model.weights,
		HiddenBias:         t.model.hiddenBias,
		OutputBias:         t.model.outputBias,
		LearningRate:       t.model.learningRate,
		ActivationFunction: t.model.activationFunction,
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "save_model_prepare",
		"key", key,
		"input_size", modelData.InputSize,
		"hidden_size", modelData.HiddenSize,
		"output_size", modelData.OutputSize,
		"weights_count", len(modelData.Weights),
		"hidden_bias_count", len(modelData.HiddenBias),
		"output_bias_count", len(modelData.OutputBias),
		"activation_function", modelData.ActivationFunction,
	)

	// Serialize the model to JSON
	// Use jsoniter without decimal truncation for ML package
	var json = jsoniter.Config{
		EscapeHTML:                    true,
		SortMapKeys:                   true,
		ValidateJsonRawMessage:        true,
		MarshalFloatWith6Digits:       false,
		ObjectFieldMustBeSimpleString: true,
	}.Froze()

	jsonData, err := json.Marshal(modelData)
	if err != nil {
		return fmt.Errorf("failed to serialize model: %w", err)
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "save_model_serialized",
		"key", key,
		"data_size", len(jsonData),
	)

	// Save to Redis
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	err = rediscli.GetClient().GetWriteHandle().Set(
		t.ctx,
		key,
		jsonData,
		30*24*time.Hour, // 30 days TTL
	).Err()

	if err != nil {
		return fmt.Errorf("failed to save model to Redis: %w", err)
	}

	// Save encodings configuration if they exist
	if (t.oneHotEncodings != nil && len(t.oneHotEncodings) > 0) ||
		(t.featureEncodingType != nil && len(t.featureEncodingType) > 0) {
		// Create a serializable representation of the encodings configuration
		encodingsData := struct {
			OneHotEncodings     map[string]map[string]int     `json:"one_hot_encodings"`
			OneHotSizes         map[string]int                `json:"one_hot_sizes"`
			FeatureEncodingType map[string]StringEncodingType `json:"feature_encoding_type"`
			EmbeddingSize       int                           `json:"embedding_size"`
		}{
			OneHotEncodings:     t.oneHotEncodings,
			OneHotSizes:         t.oneHotSizes,
			FeatureEncodingType: t.featureEncodingType,
			EmbeddingSize:       t.embeddingSize,
		}

		// Serialize the encodings to JSON
		encodingsJSON, err := json.Marshal(encodingsData)
		if err != nil {
			return fmt.Errorf("failed to serialize encodings configuration: %w", err)
		}

		// Save to Redis with a different key
		encodingsKey := key + "_encodings"
		err = rediscli.GetClient().GetWriteHandle().Set(
			t.ctx,
			encodingsKey,
			encodingsJSON,
			30*24*time.Hour, // 30 days TTL
		).Err()

		if err != nil {
			return fmt.Errorf("failed to save encodings configuration to Redis: %w", err)
		}

		util.DebugModule(definitions.DbgNeural,
			"action", "save_encodings_configuration",
			"key", encodingsKey,
			"one_hot_features_count", len(t.oneHotEncodings),
			"feature_encoding_types_count", len(t.featureEncodingType),
			"embedding_size", t.embeddingSize,
			"data_size", len(encodingsJSON),
		)

		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Encodings configuration saved to Redis successfully (key: %s)", encodingsKey),
		)
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Model saved to Redis successfully (key: %s)", key),
	)

	return nil
}

// LoadAdditionalFeaturesFromRedis loads a model with additional features from a separate Redis key
func (t *NeuralNetworkTrainer) LoadAdditionalFeaturesFromRedis() error {
	return t.LoadModelFromRedisWithKey(GetAdditionalFeaturesRedisKey())
}

// SaveAdditionalFeaturesToRedis saves a model with additional features to a separate Redis key
func (t *NeuralNetworkTrainer) SaveAdditionalFeaturesToRedis() error {
	return t.SaveModelToRedisWithKey(GetAdditionalFeaturesRedisKey())
}

// LoadModelTrainedFlagFromRedis loads the model trained flag from Redis
func LoadModelTrainedFlagFromRedis(ctx context.Context) error {
	var isModelTrained bool
	var isModelDryRun bool

	defer util.DebugModule(definitions.DbgNeural,
		"action", "load_model_trained_flag",
		"model_trained", isModelTrained,
		"model_dry_run", isModelDryRun,
	)

	key := getModelTrainedRedisKey()

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	// Get all flags from the hash map
	flags, err := rediscli.GetClient().GetReadHandle().HGetAll(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Key doesn't exist, model is not trained
			modelTrainedMutex.Lock()
			modelTrained = false
			modelDryRun = false
			modelTrainedMutex.Unlock()

			return nil
		}

		return err
	}

	// If the hash map is empty, set default values
	if len(flags) == 0 {
		modelTrainedMutex.Lock()
		modelTrained = false
		modelDryRun = false
		modelTrainedMutex.Unlock()

		return nil
	}

	// Read flags from the hash map with key existence check
	trainedValue, trainedExists := flags["trained"]
	dryRunValue, dryRunExists := flags["dry_run"]

	// Set default values if keys don't exist
	if !trainedExists {
		trainedValue = "0"
	}
	if !dryRunExists {
		dryRunValue = "0"
	}

	isModelTrained = trainedValue == "1"
	isModelDryRun = dryRunValue == "1"

	modelTrainedMutex.Lock()
	modelTrained = isModelTrained
	modelDryRun = isModelDryRun
	modelTrainedMutex.Unlock()

	return nil
}

// SaveModelTrainedFlagToRedis saves the model trained flag to Redis
func SaveModelTrainedFlagToRedis(ctx context.Context) error {
	modelTrainedMutex.RLock()
	isModelTrained := modelTrained
	isModelDryRun := modelDryRun
	modelTrainedMutex.RUnlock()

	defer util.DebugModule(definitions.DbgNeural,
		"action", "save_model_trained_flag",
		"model_trained", isModelTrained,
		"model_dry_run", isModelDryRun,
	)

	// Erstelle eine Map für die Flags
	flags := map[string]string{
		"trained": "0",
		"dry_run": "0",
	}

	if isModelTrained {
		flags["trained"] = "1"
	}
	if isModelDryRun {
		flags["dry_run"] = "1"
	}

	key := getModelTrainedRedisKey()

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	err := rediscli.GetClient().GetWriteHandle().HSet(
		ctx,
		key,
		flags,
	).Err()

	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to save model trained flags to Redis: %v", err),
		)

		return err
	}

	return nil
}
