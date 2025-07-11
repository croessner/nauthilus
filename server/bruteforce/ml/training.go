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
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/go-kit/log/level"
)

// Minimum number of samples required for training
const minSamplesForTraining = 100

// TrainingData represents a single training example with login features and result
type TrainingData struct {
	Success  bool
	Features *LoginFeatures
	Time     time.Time
	Feedback bool // True if this sample was created from user feedback
}

// StringEncodingType represents the type of encoding to use for string features
type StringEncodingType string

// NeuralNetworkTrainer handles the training of the ML model without requiring request-specific parameters
type NeuralNetworkTrainer struct {
	ctx                 context.Context
	model               *NeuralNetwork
	oneHotEncodings     map[string]map[string]int     // Maps feature name -> (value -> index)
	oneHotSizes         map[string]int                // Maps feature name -> number of possible values
	featureEncodingType map[string]StringEncodingType // Maps feature name -> encoding type (one-hot or embedding)
	embeddingSize       int                           // Size of embeddings for string features
}

// NewMLTrainer creates a new ML trainer with a default context
func NewMLTrainer() *NeuralNetworkTrainer {
	return &NeuralNetworkTrainer{
		ctx:                 context.Background(),
		oneHotEncodings:     make(map[string]map[string]int),
		oneHotSizes:         make(map[string]int),
		featureEncodingType: make(map[string]StringEncodingType),
		embeddingSize:       8, // Default embedding size
	}
}

// WithContext sets the context for the trainer
func (t *NeuralNetworkTrainer) WithContext(ctx context.Context) *NeuralNetworkTrainer {
	t.ctx = ctx

	return t
}

// SetFeatureEncodingType sets the encoding type for a specific feature
func (t *NeuralNetworkTrainer) SetFeatureEncodingType(featureName string, encodingType StringEncodingType) {
	if t.featureEncodingType == nil {
		t.featureEncodingType = make(map[string]StringEncodingType)
	}

	t.featureEncodingType[featureName] = encodingType
}

// SetEmbeddingSize sets the size of embeddings for string features
func (t *NeuralNetworkTrainer) SetEmbeddingSize(size int) {
	if size > 0 {
		t.embeddingSize = size
	}
}

// GetFeatureEncodingType returns the encoding type for a specific feature
// If no encoding type is set, it defaults to OneHotEncoding
func (t *NeuralNetworkTrainer) GetFeatureEncodingType(featureName string) StringEncodingType {
	if t.featureEncodingType == nil {
		return OneHotEncoding
	}

	if encodingType, exists := t.featureEncodingType[featureName]; exists {
		return encodingType
	}

	return OneHotEncoding
}

// generateEmbedding generates a fixed-size embedding for a string value
func (t *NeuralNetworkTrainer) generateEmbedding(value string) []float64 {
	// Initialize embedding vector with zeros
	embedding := make([]float64, t.embeddingSize)

	// If string is empty, return zero embedding
	if len(value) == 0 {
		return embedding
	}

	// Generate a deterministic embedding based on the string content
	// This approach ensures that similar strings produce similar embeddings
	for i, char := range value {
		// Use character value and position to influence all dimensions of the embedding
		for j := 0; j < t.embeddingSize; j++ {
			// Different formula for each dimension to create varied embeddings
			switch j % 4 {
			case 0:
				// Use character value directly
				embedding[j] += float64(char) / 256.0 / float64(i+1)
			case 1:
				// Use character position
				embedding[j] += float64(i) / float64(len(value)) * float64(char%64) / 64.0
			case 2:
				// Combine character value and position
				embedding[j] += math.Sin(float64(char) * float64(i+1) / 100.0)
			case 3:
				// Another combination
				embedding[j] += math.Cos(float64(char) / float64(i+1))
			}
		}
	}

	// Normalize the embedding to have values between 0 and 1
	var sum float64

	for _, val := range embedding {
		sum += val * val
	}

	// Avoid division by zero
	if sum > 0 {
		magnitude := math.Sqrt(sum)
		for i := range embedding {
			// Scale to [0, 1] range
			embedding[i] = (embedding[i]/magnitude + 1.0) / 2.0
		}
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "generate_embedding",
		"value", value,
		"embedding_size", t.embeddingSize,
		"embedding_vector", embedding,
		"vector_sum", sum,
		"magnitude", math.Sqrt(sum),
	)

	return embedding
}

// getOrCreateOneHotEncoding returns the one-hot encoding size and index for a categorical feature value
// If the feature or value hasn't been seen before, it creates a new encoding
func (t *NeuralNetworkTrainer) getOrCreateOneHotEncoding(featureName string, value string) (int, int) {
	// Initialize maps if they don't exist
	if t.oneHotEncodings == nil {
		t.oneHotEncodings = make(map[string]map[string]int)
	}

	if t.oneHotSizes == nil {
		t.oneHotSizes = make(map[string]int)
	}

	// Check if we've seen this feature before
	if _, exists := t.oneHotEncodings[featureName]; !exists {
		t.oneHotEncodings[featureName] = make(map[string]int)
		t.oneHotSizes[featureName] = 0
	}

	// Check if we've seen this value before
	if index, exists := t.oneHotEncodings[featureName][value]; exists {
		return t.oneHotSizes[featureName], index
	}

	// Add new value
	newIndex := t.oneHotSizes[featureName]

	t.oneHotEncodings[featureName][value] = newIndex
	t.oneHotSizes[featureName]++

	util.DebugModule(definitions.DbgNeural,
		"action", "new_categorical_value",
		"feature", featureName,
		"value", value,
		"index", newIndex,
		"total_values", t.oneHotSizes[featureName],
	)

	return t.oneHotSizes[featureName], newIndex
}

// calculateFeatureNeuronCount returns the number of neurons needed for a feature based on its encoding type
func (t *NeuralNetworkTrainer) calculateFeatureNeuronCount(featureName string) int {
	encodingType := t.GetFeatureEncodingType(featureName)

	switch encodingType {
	case EmbeddingEncoding:
		// For embedding encoding, use the embedding size
		return t.embeddingSize
	case OneHotEncoding:
		// For one-hot encoding, use the number of possible values
		if size, exists := t.oneHotSizes[featureName]; exists && size > 0 {
			return size
		}
		// If we don't have any values yet, default to 1
		return 1
	default:
		// For numeric features or unknown encoding types, use 1 neuron
		return 1
	}
}

// InitModel initializes the neural network model
func (t *NeuralNetworkTrainer) InitModel() {
	util.DebugModule(definitions.DbgNeural,
		"action", "init_model_start",
	)

	// Default input size is 6 for the standard features
	inputSize := 6
	additionalFeatureCount := 0
	additionalNeuronCount := 0

	// Skip dynamic neuron adjustment during tests
	if os.Getenv("NAUTHILUS_TESTING") != "1" {
		// First, try to get the canonical list of features from Redis
		canonicalFeatures, err := GetDynamicFeaturesFromRedis(t.ctx)
		if err == nil && len(canonicalFeatures) > 0 {
			// Calculate the actual neuron count for each feature
			additionalFeatureCount = len(canonicalFeatures)
			for _, featureName := range canonicalFeatures {
				neuronCount := t.calculateFeatureNeuronCount(featureName)
				additionalNeuronCount += neuronCount

				util.DebugModule(definitions.DbgNeural,
					"action", "calculate_feature_neurons",
					"feature_name", featureName,
					"encoding_type", t.GetFeatureEncodingType(featureName),
					"neuron_count", neuronCount,
				)
			}

			// Add the total neuron count to the input size
			inputSize += additionalNeuronCount

			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Initializing model with %d input neurons (%d standard + %d dynamic from %d features) based on canonical feature list",
					inputSize, 6, additionalNeuronCount, additionalFeatureCount),
				"features", strings.Join(canonicalFeatures, ", "),
			)

			util.DebugModule(definitions.DbgNeural,
				"action", "init_model_with_canonical_features",
				"additional_features_count", additionalFeatureCount,
				"additional_neurons_count", additionalNeuronCount,
				"total_input_size", inputSize,
			)
		} else {
			// If we couldn't get the canonical list, fall back to checking training data and context

			// Check if we have any training data with additional features
			trainingData, err := t.GetTrainingDataFromRedis(1)
			if err == nil && len(trainingData) > 0 && trainingData[0].Features != nil &&
				trainingData[0].Features.AdditionalFeatures != nil && len(trainingData[0].Features.AdditionalFeatures) > 0 {

				// Calculate the actual neuron count for each feature
				additionalFeatureCount = len(trainingData[0].Features.AdditionalFeatures)
				var featureNames []string

				for featureName := range trainingData[0].Features.AdditionalFeatures {
					featureNames = append(featureNames, featureName)
					neuronCount := t.calculateFeatureNeuronCount(featureName)
					additionalNeuronCount += neuronCount

					util.DebugModule(definitions.DbgNeural,
						"action", "calculate_feature_neurons_from_training",
						"feature_name", featureName,
						"encoding_type", t.GetFeatureEncodingType(featureName),
						"neuron_count", neuronCount,
					)
				}

				// Add the total neuron count to the input size
				inputSize += additionalNeuronCount

				// Store these features in the canonical list for future use
				if storeErr := StoreDynamicFeaturesToRedis(t.ctx, featureNames); storeErr != nil {
					level.Warn(log.Logger).Log(
						definitions.LogKeyMsg, fmt.Sprintf("Failed to store training data features to canonical list: %v", storeErr),
					)
				}

				util.DebugModule(definitions.DbgNeural,
					"action", "init_model_with_additional_features_from_training",
					"additional_features_count", additionalFeatureCount,
					"additional_neurons_count", additionalNeuronCount,
					"total_input_size", inputSize,
				)
			}

			// Also check if we have additional features from Lua context
			// This ensures we account for newly added Lua features that haven't been saved to training data yet
			if t.ctx != nil {
				if additionalFeatures, ok := t.ctx.Value(definitions.CtxAdditionalFeaturesKey).(map[string]any); ok && len(additionalFeatures) > 0 {
					// If we have additional features from context, ensure they're counted in the input size
					// We need to check if these features are already counted from training data
					if err != nil || len(trainingData) == 0 || trainingData[0].Features == nil ||
						trainingData[0].Features.AdditionalFeatures == nil {
						// No training data features, add all context features
						contextFeatureCount := len(additionalFeatures)
						contextNeuronCount := 0
						var featureNames []string

						for featureName := range additionalFeatures {
							featureNames = append(featureNames, featureName)
							neuronCount := t.calculateFeatureNeuronCount(featureName)
							contextNeuronCount += neuronCount

							util.DebugModule(definitions.DbgNeural,
								"action", "calculate_feature_neurons_from_context",
								"feature_name", featureName,
								"encoding_type", t.GetFeatureEncodingType(featureName),
								"neuron_count", neuronCount,
							)
						}

						// Add the total neuron count to the input size
						inputSize += contextNeuronCount
						additionalFeatureCount = contextFeatureCount
						additionalNeuronCount = contextNeuronCount

						// Store these features in the canonical list for future use
						if storeErr := StoreDynamicFeaturesToRedis(t.ctx, featureNames); storeErr != nil {
							level.Warn(log.Logger).Log(
								definitions.LogKeyMsg, fmt.Sprintf("Failed to store context features to canonical list: %v", storeErr),
							)
						}

						util.DebugModule(definitions.DbgNeural,
							"action", "init_model_with_additional_features_from_context",
							"additional_features_count", contextFeatureCount,
							"additional_neurons_count", contextNeuronCount,
							"total_input_size", inputSize,
						)
					} else {
						// We have both training data features and context features
						// Count any context features not in training data
						var newFeatures []string
						contextNeuronCount := 0

						for featureName := range additionalFeatures {
							if _, exists := trainingData[0].Features.AdditionalFeatures[featureName]; !exists {
								// This feature is in context but not in training data
								newFeatures = append(newFeatures, featureName)
								neuronCount := t.calculateFeatureNeuronCount(featureName)
								contextNeuronCount += neuronCount

								util.DebugModule(definitions.DbgNeural,
									"action", "calculate_feature_neurons_from_new_context",
									"feature_name", featureName,
									"encoding_type", t.GetFeatureEncodingType(featureName),
									"neuron_count", neuronCount,
									"total_input_size", inputSize+contextNeuronCount,
								)
							}
						}

						// Add the total neuron count to the input size
						inputSize += contextNeuronCount
						additionalNeuronCount += contextNeuronCount

						// Store any new features in the canonical list
						if len(newFeatures) > 0 {
							if storeErr := StoreDynamicFeaturesToRedis(t.ctx, newFeatures); storeErr != nil {
								level.Warn(log.Logger).Log(
									definitions.LogKeyMsg, fmt.Sprintf("Failed to store new context features to canonical list: %v", storeErr),
								)
							}
						}
					}
				}
			}
		}
	} else {
		util.DebugModule(definitions.DbgNeural,
			"action", "skip_dynamic_neuron_adjustment_in_init_model",
			"reason", "running_in_test_environment",
			"input_size", inputSize,
		)
	}

	// Create a neural network with the appropriate number of input neurons,
	// 8 hidden neurons, and 1 output neuron (probability of brute force)
	t.model = NewNeuralNetwork(inputSize, 1)

	// Ensure metrics are updated with the correct input size
	GetMLMetrics().RecordNetworkStructure(inputSize, t.model.hiddenSize, 1)

	util.DebugModule(definitions.DbgNeural,
		"action", "init_model_complete",
		"input_size", inputSize,
		"hidden_size", t.model.hiddenSize,
		"output_size", 1,
	)
}

// GetTrainingDataFromRedis retrieves the stored training data from Redis
// with balanced ratio of successful and failed login attempts
func (t *NeuralNetworkTrainer) GetTrainingDataFromRedis(maxSamples int) ([]TrainingData, error) {
	util.DebugModule(definitions.DbgNeural,
		"action", "get_training_data_start",
		"max_samples", maxSamples,
	)

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:training:data"

	// Limit the number of samples to retrieve
	if maxSamples <= 0 {
		maxSamples = 1000 // Default to 1000 samples

		util.DebugModule(definitions.DbgNeural,
			"action", "get_training_data_default_samples",
			"max_samples", maxSamples,
		)
	}

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	// Get all available training data from Redis (we'll balance it later)
	// We retrieve more than maxSamples to ensure we have enough of each class
	retrieveSamples := maxSamples * 3 // Get more samples to ensure we have enough of each class
	jsonData, err := rediscli.GetClient().GetReadHandle().LRange(t.ctx, key, 0, int64(retrieveSamples-1)).Result()
	if err != nil {
		return nil, err
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "get_training_data_received",
		"samples_count", len(jsonData),
	)

	// Parse the JSON data into TrainingData objects
	var successfulSamples []TrainingData
	var failedSamples []TrainingData

	parseErrors := 0

	for _, data := range jsonData {
		var sample TrainingData

		if err := json.Unmarshal([]byte(data), &sample); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Error parsing training data: %v", err),
			)

			parseErrors++

			continue
		}

		// Separate samples into successful and failed login attempts
		if sample.Success {
			successfulSamples = append(successfulSamples, sample)
		} else {
			failedSamples = append(failedSamples, sample)
		}
	}

	// Balance the dataset with a maximum ratio of 80:20 between classes
	// This prevents the model from being biased towards one class
	balancedData := balanceTrainingData(successfulSamples, failedSamples, maxSamples)

	util.DebugModule(definitions.DbgNeural,
		"action", "get_training_data_complete",
		"samples_parsed", len(balancedData),
		"successful_samples", len(successfulSamples),
		"failed_samples", len(failedSamples),
		"balanced_samples", len(balancedData),
		"parse_errors", parseErrors,
	)

	return balancedData, nil
}

// balanceTrainingData ensures a balanced ratio between successful and failed login attempts
// to prevent the model from being biased towards one class.
//
// This function implements the 80:20 rule, where no class (successful or failed logins)
// should represent more than 80% of the training data. This prevents the model from
// becoming biased towards one class, which could lead to either:
// 1. Too many false positives (if trained mostly on failed logins)
// 2. Too many false negatives (if trained mostly on successful logins)
//
// The function takes the available successful and failed samples, calculates the
// appropriate ratio, and returns a balanced dataset for training.
func balanceTrainingData(successfulSamples, failedSamples []TrainingData, maxSamples int) []TrainingData {
	// Calculate the total number of samples we want
	totalSamples := maxSamples
	if totalSamples > len(successfulSamples)+len(failedSamples) {
		totalSamples = len(successfulSamples) + len(failedSamples)
	}

	// If there are no samples at all, return an empty slice
	successCount := len(successfulSamples)
	failedCount := len(failedSamples)

	if successCount+failedCount == 0 {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "No training data available for balancing",
		)

		return []TrainingData{}
	}

	// Define the maximum ratio between classes (80:20 rule)
	// No class should represent more than 80% of the data
	maxRatio := 0.8
	minRatio := 1.0 - maxRatio // 0.2

	// Calculate the ratio of successful samples in the original data
	originalSuccessRatio := float64(successCount) / float64(successCount+failedCount)

	// Determine how many samples of each class to include
	var successSamplesToUse, failedSamplesToUse int

	if originalSuccessRatio > maxRatio {
		// Too many successful samples, cap at maxRatio
		// This prevents the model from being biased towards successful logins
		successSamplesToUse = int(float64(totalSamples) * maxRatio)
		failedSamplesToUse = totalSamples - successSamplesToUse
	} else if originalSuccessRatio < minRatio {
		// Too many failed samples, cap at minRatio for successful samples
		// This prevents the model from being biased towards failed logins
		successSamplesToUse = int(float64(totalSamples) * minRatio)
		failedSamplesToUse = totalSamples - successSamplesToUse
	} else {
		// The ratio is already within acceptable bounds, maintain it
		// This preserves the natural distribution when it's already balanced
		successSamplesToUse = int(float64(totalSamples) * originalSuccessRatio)
		failedSamplesToUse = totalSamples - successSamplesToUse
	}

	// Ensure we don't request more samples than available
	if successSamplesToUse > successCount {
		successSamplesToUse = successCount
	}
	if failedSamplesToUse > failedCount {
		failedSamplesToUse = failedCount
	}

	// Shuffle and select the required number of samples from each class
	// This ensures we get a random selection rather than just the most recent
	// which helps prevent temporal bias in the training data
	rand.Shuffle(len(successfulSamples), func(i, j int) {
		successfulSamples[i], successfulSamples[j] = successfulSamples[j], successfulSamples[i]
	})
	rand.Shuffle(len(failedSamples), func(i, j int) {
		failedSamples[i], failedSamples[j] = failedSamples[j], failedSamples[i]
	})

	// Select the required number of samples from each class
	successfulSamples = successfulSamples[:successSamplesToUse]
	failedSamples = failedSamples[:failedSamplesToUse]

	// Combine and shuffle the balanced dataset
	balancedData := append(successfulSamples, failedSamples...)
	rand.Shuffle(len(balancedData), func(i, j int) {
		balancedData[i], balancedData[j] = balancedData[j], balancedData[i]
	})

	// Log the balancing results
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Balanced training data: %d successful, %d failed (%.1f%% successful)",
			successSamplesToUse, failedSamplesToUse, float64(successSamplesToUse)/float64(successSamplesToUse+failedSamplesToUse)*100),
	)

	return balancedData
}

// PrepareTrainingData converts the raw training data into features and labels for the neural network
func (t *NeuralNetworkTrainer) PrepareTrainingData(data []TrainingData) ([][]float64, [][]float64) {
	util.DebugModule(definitions.DbgNeural,
		"action", "prepare_training_data_start",
		"data_samples", len(data),
	)

	if len(data) == 0 {
		return nil, nil
	}

	features := make([][]float64, 0, len(data))
	labels := make([][]float64, 0, len(data))
	skippedSamples := 0

	for i, sample := range data {
		if sample.Features == nil {
			skippedSamples++

			continue
		}

		// Start with standard features
		featureVector := []float64{
			sample.Features.TimeBetweenAttempts,
			sample.Features.FailedAttemptsLastHour,
			sample.Features.DifferentUsernames,
			sample.Features.DifferentPasswords,
			sample.Features.TimeOfDay,
			sample.Features.SuspiciousNetwork,
		}

		// Add additional features if they exist
		if sample.Features.AdditionalFeatures != nil && len(sample.Features.AdditionalFeatures) > 0 {
			util.DebugModule(definitions.DbgNeural,
				"action", "prepare_training_data_additional_features",
				"additional_features_count", len(sample.Features.AdditionalFeatures),
				"sample_index", i,
			)

			// Sort keys for consistent order
			keys := make([]string, 0, len(sample.Features.AdditionalFeatures))
			for k := range sample.Features.AdditionalFeatures {
				keys = append(keys, k)
			}

			sort.Strings(keys)

			// Add each additional feature to the inputs
			for _, key := range keys {
				value := sample.Features.AdditionalFeatures[key]

				// Process the value based on its type
				switch v := value.(type) {
				case float64:
					featureVector = append(featureVector, v)
				case float32:
					featureVector = append(featureVector, float64(v))
				case int:
					featureVector = append(featureVector, float64(v))
				case int64:
					featureVector = append(featureVector, float64(v))
				case bool:
					if v {
						featureVector = append(featureVector, 1.0)
					} else {
						featureVector = append(featureVector, 0.0)
					}
				case string:
					// Check the encoding type for this feature
					encodingType := t.GetFeatureEncodingType(key)

					if encodingType == EmbeddingEncoding {
						// Use embedding encoding for this feature
						embedding := t.generateEmbedding(v)
						featureVector = append(featureVector, embedding...)

						util.DebugModule(definitions.DbgNeural,
							"action", "prepare_training_data_embedding",
							"key", key,
							"value", v,
							"embedding_size", len(embedding),
							"sample_index", i,
						)
					} else {
						// For categorical string values, use one-hot encoding (default)
						// Get or create the one-hot encoding for this feature
						oneHotValues, oneHotIndex := t.getOrCreateOneHotEncoding(key, v)

						// Add one-hot encoded values to the feature vector
						for j := 0; j < oneHotValues; j++ {
							if j == oneHotIndex {
								featureVector = append(featureVector, 1.0)
							} else {
								featureVector = append(featureVector, 0.0)
							}
						}

						util.DebugModule(definitions.DbgNeural,
							"action", "one_hot_encoding",
							"key", key,
							"value", v,
							"one_hot_values", oneHotValues,
							"one_hot_index", oneHotIndex,
							"sample_index", i,
						)
					}
				default:
					// For other types, use a default value
					featureVector = append(featureVector, 0.5)
				}

				util.DebugModule(definitions.DbgNeural,
					"action", "prepare_training_data_additional_feature",
					"key", key,
					"value", value,
					"sample_index", i,
				)
			}
		}

		// Normalize the features
		normalizedFeatures := normalizeInputs(featureVector)
		features = append(features, normalizedFeatures)

		// Create label (1 for legitimate login, 0 for brute force)
		// In this simplified model, we assume success=true means legitimate
		var label float64

		if sample.Success {
			label = 1.0 // Legitimate login
		} else {
			label = 0.0 // Potential brute force
		}

		labels = append(labels, []float64{label})
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "prepare_training_data_complete",
		"features_count", len(features),
		"labels_count", len(labels),
		"skipped_samples", skippedSamples,
	)

	return features, labels
}

// normalizeInputs normalizes the input features to a range suitable for the neural network
func normalizeInputs(inputs []float64) []float64 {
	// Define normalization ranges for each standard feature
	standardRanges := []struct {
		min float64
		max float64
	}{
		{0, 3600}, // TimeBetweenAttempts (0 to 1 hour)
		{0, 100},  // FailedAttemptsLastHour
		{0, 20},   // DifferentUsernames
		{0, 20},   // DifferentPasswords
		{0, 1},    // TimeOfDay (already normalized)
		{0, 1},    // SuspiciousNetwork (already normalized)
	}

	normalized := make([]float64, len(inputs))
	for i, val := range inputs {
		if i < len(standardRanges) {
			// Apply min-max normalization for standard features
			normalized[i] = (val - standardRanges[i].min) / (standardRanges[i].max - standardRanges[i].min)
		} else {
			// For additional features, use a default range of 0-1
			// This assumes additional features are already normalized or will be normalized by the caller
			normalized[i] = val

			// If the value is outside the range [0,1], clamp it
			if normalized[i] < 0 {
				normalized[i] = 0
			} else if normalized[i] > 1 {
				normalized[i] = 1
			}
		}

		// Ensure values are within [0,1]
		if normalized[i] < 0 {
			normalized[i] = 0
		} else if normalized[i] > 1 {
			normalized[i] = 1
		}
	}

	return normalized
}

// TrainWithStoredData retrieves training data from Redis and trains the model
func (t *NeuralNetworkTrainer) TrainWithStoredData(maxSamples int, epochs int) error {
	util.DebugModule(definitions.DbgNeural,
		"action", "train_with_stored_data_start",
		"max_samples", maxSamples,
		"epochs", epochs,
	)

	// Initialize the model if it doesn't exist
	if t.model == nil {
		// Try to load a previously trained model first
		if loadErr := t.LoadModelFromRedis(); loadErr != nil {
			// Fall back to initializing with random weights
			t.InitModel()
		}
	}

	// Get training data from Redis
	trainingData, err := t.GetTrainingDataFromRedis(maxSamples)
	if err != nil {
		return fmt.Errorf("failed to retrieve training data: %w", err)
	}

	if len(trainingData) == 0 {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "No training data available in Redis",
		)

		return nil
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Retrieved %d training samples from Redis", len(trainingData)),
	)

	// Check if we have enough samples to start training
	if len(trainingData) < minSamplesForTraining {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Not enough training samples (%d). Need at least %d samples before training starts.",
				len(trainingData), minSamplesForTraining),
		)

		return nil
	}

	// Prepare the data for training
	features, labels := t.PrepareTrainingData(trainingData)
	if len(features) == 0 || len(labels) == 0 {
		util.DebugModule(definitions.DbgNeural,
			"action", "train_with_stored_data_error",
			"reason", "prepare_training_data_failed",
			"features_count", len(features),
			"labels_count", len(labels),
		)

		return fmt.Errorf("failed to prepare training data")
	}

	// Train the model
	util.DebugModule(definitions.DbgNeural,
		"action", "train_with_stored_data_train_model",
		"features_count", len(features),
		"labels_count", len(labels),
		"epochs", epochs,
	)

	// Record the start time for training duration metric
	startTime := time.Now()

	t.model.Train(features, labels, epochs)

	// Calculate and record the training duration
	trainingDuration := time.Since(startTime).Seconds()
	GetMLMetrics().RecordTrainingDuration(trainingDuration, true)

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Model training completed successfully in %.2f seconds", trainingDuration),
	)

	// Set the modelTrained flag.
	modelTrainedMutex.Lock()
	modelTrained = true
	modelTrainedMutex.Unlock()

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Model is now considered trained with real data",
	)

	// Save the flag to Redis for future use
	if saveErr := SaveModelTrainedFlagToRedis(t.ctx); saveErr != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to save model trained flag to Redis: %v", saveErr),
		)
	}

	return nil
}

// GetModel returns the trained neural network model
func (t *NeuralNetworkTrainer) GetModel() *NeuralNetwork {
	return t.model
}
