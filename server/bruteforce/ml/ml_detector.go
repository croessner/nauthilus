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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
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

var httpClient *http.Client

// InitHTTPClient initializes and assigns a new HTTP client to the package-wide httpClient variable.
func InitHTTPClient() {
	httpClient = util.NewHTTPClient()
}

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

// NeuralNetwork is a simplified implementation of a neural network
type NeuralNetwork struct {
	inputSize          int
	hiddenSize         int
	outputSize         int
	weights            []float64  // In a real implementation, this would be a more complex structure
	learningRate       float64    // Learning rate for training
	rng                *rand.Rand // Random number generator
	activationFunction string     // Activation function to use (sigmoid, tanh, relu, leaky_relu)
}

// NewNeuralNetwork creates a new neural network with the specified layer sizes
func NewNeuralNetwork(inputSize, outputSize int) *NeuralNetwork {
	return NewNeuralNetworkWithSeed(inputSize, outputSize, time.Now().UnixNano())
}

// NewNeuralNetworkWithSeed creates a new neural network with the specified layer sizes and a fixed seed for reproducibility
func NewNeuralNetworkWithSeed(inputSize, outputSize int, seed int64) *NeuralNetwork {
	var hiddenSize int

	hiddenSizeConf := config.GetFile().GetBruteForce().GetNeuralNetwork().HiddenNeurons
	if hiddenSizeConf == 0 {
		hiddenSize = 10
	} else {
		hiddenSize = hiddenSizeConf
	}

	// Get activation function from config or use default
	activationFunction := config.GetFile().GetBruteForce().GetNeuralNetwork().ActivationFunction
	if activationFunction == "" {
		activationFunction = "sigmoid" // Default to sigmoid if not specified
	}

	// Debug: Log neural network creation
	util.DebugModule(definitions.DbgNeural,
		"action", "create_neural_network",
		"input_size", inputSize,
		"hidden_size", hiddenSize,
		"output_size", outputSize,
		"activation_function", activationFunction,
		"seed", seed,
	)

	// Create a new random number generator with the provided seed
	source := rand.NewSource(seed)
	rng := rand.New(source)

	// Create a new neural network with properly initialized weights
	nn := &NeuralNetwork{
		inputSize:          inputSize,
		hiddenSize:         hiddenSize,
		outputSize:         outputSize,
		weights:            make([]float64, inputSize*hiddenSize+hiddenSize*outputSize),
		learningRate:       0.01, // Default learning rate
		rng:                rng,
		activationFunction: activationFunction,
	}

	// Initialize weights with small random values
	for i := range nn.weights {
		nn.weights[i] = (nn.rng.Float64() - 0.5) * 0.1
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "neural_network_created",
		"weights_count", len(nn.weights),
	)

	// Record network structure metrics
	GetMLMetrics().RecordNetworkStructure(inputSize, hiddenSize, outputSize)

	// Record initial weight values
	nn.recordWeightMetrics()

	return nn
}

// Train trains the neural network with the provided features and labels for a specified number of epochs
func (nn *NeuralNetwork) Train(features [][]float64, labels [][]float64, epochs int) {
	util.DebugModule(definitions.DbgNeural,
		"action", "train_start",
		"features_count", len(features),
		"labels_count", len(labels),
		"epochs", epochs,
	)

	// Record the number of training samples
	GetMLMetrics().RecordTrainingSamplesUsed(len(features))

	if len(features) == 0 || len(labels) == 0 {
		util.DebugModule(definitions.DbgNeural,
			"action", "train_abort",
			"reason", "no_training_data",
		)

		return // Nothing to train on
	}

	// Initialize weights if they haven't been initialized properly
	if len(nn.weights) != nn.inputSize*nn.hiddenSize+nn.hiddenSize*nn.outputSize {
		util.DebugModule(definitions.DbgNeural,
			"action", "reinitialize_weights",
			"expected_size", nn.inputSize*nn.hiddenSize+nn.hiddenSize*nn.outputSize,
			"actual_size", len(nn.weights),
		)

		nn.weights = make([]float64, nn.inputSize*nn.hiddenSize+nn.hiddenSize*nn.outputSize)
		// Initialize weights with small random values
		for i := range nn.weights {
			nn.weights[i] = (nn.rng.Float64() - 0.5) * 0.1
		}
	}

	// Implementation of stochastic gradient descent with backpropagation
	for epoch := 0; epoch < epochs; epoch++ {
		totalError := 0.0

		// Shuffle the training data
		indices := nn.rng.Perm(len(features))

		// Iterate through each training example
		for _, idx := range indices {
			if idx >= len(labels) {
				continue // Skip if no corresponding label
			}

			inputFeatures := features[idx]
			targetLabels := labels[idx]

			if len(inputFeatures) != nn.inputSize || len(targetLabels) != nn.outputSize {
				util.DebugModule(definitions.DbgNeural,
					"action", "skip_training_example",
					"reason", "dimension_mismatch",
					"input_size", len(inputFeatures),
					"expected_input_size", nn.inputSize,
					"output_size", len(targetLabels),
					"expected_output_size", nn.outputSize,
				)

				continue // Skip if dimensions don't match
			}

			// Forward pass
			// 1. Calculate hidden layer activations
			hiddenActivations := make([]float64, nn.hiddenSize)
			hiddenNetInputs := make([]float64, nn.hiddenSize) // Store net inputs for backprop
			for i := 0; i < nn.hiddenSize; i++ {
				sum := 0.0
				for j := 0; j < nn.inputSize; j++ {
					weightIndex := i*nn.inputSize + j
					if weightIndex < len(nn.weights) {
						sum += inputFeatures[j] * nn.weights[weightIndex]
					}
				}

				hiddenNetInputs[i] = sum
				hiddenActivations[i] = nn.activate(sum) // Apply activation function
			}

			// 2. Calculate output layer activations
			outputActivations := make([]float64, nn.outputSize)
			outputNetInputs := make([]float64, nn.outputSize) // Store net inputs for backprop

			for i := 0; i < nn.outputSize; i++ {
				sum := 0.0
				for j := 0; j < nn.hiddenSize; j++ {
					weightIndex := nn.inputSize*nn.hiddenSize + i*nn.hiddenSize + j
					if weightIndex < len(nn.weights) {
						sum += hiddenActivations[j] * nn.weights[weightIndex]
					}
				}

				outputNetInputs[i] = sum
				outputActivations[i] = nn.activate(sum) // Apply activation function
			}

			// Calculate error
			outputErrors := make([]float64, nn.outputSize)
			for i := 0; i < nn.outputSize; i++ {
				if i < len(targetLabels) {
					errorValue := targetLabels[i] - outputActivations[i]
					outputErrors[i] = errorValue
					totalError += errorValue * errorValue // Squared error
				}
			}

			// Backpropagation
			// 1. Calculate output layer deltas
			outputDeltas := make([]float64, nn.outputSize)
			for i := 0; i < nn.outputSize; i++ {
				// Delta = error * derivative of activation function
				derivative := nn.activateDerivative(outputNetInputs[i])
				outputDeltas[i] = outputErrors[i] * derivative
			}

			// 2. Calculate hidden layer deltas
			hiddenDeltas := make([]float64, nn.hiddenSize)
			for i := 0; i < nn.hiddenSize; i++ {
				errorValue := 0.0
				for j := 0; j < nn.outputSize; j++ {
					weightIndex := nn.inputSize*nn.hiddenSize + j*nn.hiddenSize + i
					if weightIndex < len(nn.weights) {
						errorValue += outputDeltas[j] * nn.weights[weightIndex]
					}
				}

				derivative := nn.activateDerivative(hiddenNetInputs[i])
				hiddenDeltas[i] = errorValue * derivative
			}

			// 3. Update weights
			// Update weights between input and hidden layers
			for i := 0; i < nn.hiddenSize; i++ {
				for j := 0; j < nn.inputSize; j++ {
					weightIndex := i*nn.inputSize + j
					if weightIndex < len(nn.weights) {
						delta := nn.learningRate * hiddenDeltas[i] * inputFeatures[j]
						nn.weights[weightIndex] += delta
					}
				}
			}

			// Update weights between hidden and output layers
			for i := 0; i < nn.outputSize; i++ {
				for j := 0; j < nn.hiddenSize; j++ {
					weightIndex := nn.inputSize*nn.hiddenSize + i*nn.hiddenSize + j
					if weightIndex < len(nn.weights) {
						delta := nn.learningRate * outputDeltas[i] * hiddenActivations[j]
						nn.weights[weightIndex] += delta
					}
				}
			}
		}

		// Log progress every 10 epochs
		if epoch%10 == 0 {
			avgError := totalError / float64(len(features))

			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Epoch %d: Average error = %.6f", epoch, avgError),
			)

			util.DebugModule(definitions.DbgNeural,
				"action", "epoch_progress",
				"epoch", epoch,
				"total_epochs", epochs,
				"average_error", avgError,
			)

			// Record training error metrics
			GetMLMetrics().RecordTrainingError(epoch, avgError)
		}
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "train_complete",
		"epochs_completed", epochs,
	)

	// Record final weight values after training
	nn.recordWeightMetrics()
}

// recordWeightMetrics records the current weight values as Prometheus metrics
func (nn *NeuralNetwork) recordWeightMetrics() {
	metrics := GetMLMetrics()

	// Record weights between input and hidden layers
	for i := 0; i < nn.hiddenSize; i++ {
		for j := 0; j < nn.inputSize; j++ {
			weightIndex := i*nn.inputSize + j
			if weightIndex < len(nn.weights) {
				metrics.RecordWeightValue("input", j, "hidden", i, nn.weights[weightIndex])
			}
		}
	}

	// Record weights between hidden and output layers
	for i := 0; i < nn.outputSize; i++ {
		for j := 0; j < nn.hiddenSize; j++ {
			weightIndex := nn.inputSize*nn.hiddenSize + i*nn.hiddenSize + j
			if weightIndex < len(nn.weights) {
				metrics.RecordWeightValue("hidden", j, "output", i, nn.weights[weightIndex])
			}
		}
	}
}

// activate applies the selected activation function to the input
func (nn *NeuralNetwork) activate(x float64) float64 {
	switch nn.activationFunction {
	case "tanh":
		return math.Tanh(x)
	case "relu":
		if x > 0 {
			return x
		}

		return 0
	case "leaky_relu":
		if x > 0 {
			return x
		}

		return 0.01 * x // Alpha value of 0.01 for leaky ReLU
	default: // "sigmoid" or any other value defaults to sigmoid
		return 1.0 / (1.0 + math.Exp(-x))
	}
}

// activateDerivative calculates the derivative of the selected activation function
func (nn *NeuralNetwork) activateDerivative(x float64) float64 {
	switch nn.activationFunction {
	case "tanh":
		// Derivative of tanh(x) is 1 - tanh²(x)
		tanhX := math.Tanh(x)

		return 1.0 - tanhX*tanhX
	case "relu":
		if x > 0 {
			return 1.0
		}

		return 0.0
	case "leaky_relu":
		if x > 0 {
			return 1.0
		}

		return 0.01 // Alpha value of 0.01 for leaky ReLU
	default: // "sigmoid" or any other value defaults to sigmoid
		// For sigmoid, we can use the property that sigmoid'(x) = sigmoid(x) * (1 - sigmoid(x))
		sigmoidX := 1.0 / (1.0 + math.Exp(-x))

		return sigmoidX * (1.0 - sigmoidX)
	}
}

// FeedForward performs forward propagation through the network
func (nn *NeuralNetwork) FeedForward(inputs []float64) []float64 {
	util.DebugModule(definitions.DbgNeural,
		"action", "feed_forward_start",
		"input_size", len(inputs),
	)

	if len(inputs) < nn.inputSize {
		// Handle error: not enough inputs for the network
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Not enough inputs: expected at least %d, got %d", nn.inputSize, len(inputs)),
		)

		util.DebugModule(definitions.DbgNeural,
			"action", "feed_forward_error",
			"reason", "insufficient_inputs",
			"input_size", len(inputs),
			"expected_input_size", nn.inputSize,
		)

		// Return a default value
		return []float64{0.5}
	}

	// If there are more inputs than expected, log a warning but continue with the first nn.inputSize inputs
	if len(inputs) > nn.inputSize {
		util.DebugModule(definitions.DbgNeural,
			"action", "feed_forward_warning",
			"reason", "extra_inputs",
			"input_size", len(inputs),
			"using_input_size", nn.inputSize,
		)
	}

	// Implement a simple feed-forward neural network with one hidden layer
	// 1. Calculate hidden layer activations

	// Use the actual number of inputs, but limit to nn.inputSize to match the weights
	actualInputSize := len(inputs)
	if actualInputSize > nn.inputSize {
		actualInputSize = nn.inputSize
	}

	hiddenActivations := make([]float64, nn.hiddenSize)
	for i := 0; i < nn.hiddenSize; i++ {
		sum := 0.0
		for j := 0; j < actualInputSize; j++ {
			// Get weight from input j to hidden i
			weightIndex := i*nn.inputSize + j
			if weightIndex < len(nn.weights) {
				sum += inputs[j] * nn.weights[weightIndex]
			}
		}

		// Apply activation function
		activation := nn.activate(sum)
		hiddenActivations[i] = activation

		// Record neuron activation metrics
		GetMLMetrics().RecordNeuronActivation("hidden", i, activation)
	}

	// 2. Calculate output layer activations

	outputs := make([]float64, nn.outputSize)
	for i := 0; i < nn.outputSize; i++ {
		sum := 0.0
		for j := 0; j < nn.hiddenSize; j++ {
			// Get weight from hidden j to output i
			weightIndex := nn.inputSize*nn.hiddenSize + i*nn.hiddenSize + j
			if weightIndex < len(nn.weights) {
				sum += hiddenActivations[j] * nn.weights[weightIndex]
			}
		}

		// Apply activation function
		activation := nn.activate(sum)
		outputs[i] = activation

		// Record neuron activation metrics
		GetMLMetrics().RecordNeuronActivation("output", i, activation)
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "feed_forward_complete",
		"output", fmt.Sprintf("%v", outputs),
	)

	return outputs
}

// TrainingData represents a single training example with login features and result
type TrainingData struct {
	Success  bool
	Features *LoginFeatures
	Time     time.Time
}

// MLTrainer handles the training of the ML model without requiring request-specific parameters
type MLTrainer struct {
	ctx   context.Context
	model *NeuralNetwork
}

// NewMLTrainer creates a new ML trainer with a default context
func NewMLTrainer() *MLTrainer {
	return &MLTrainer{
		ctx: context.Background(),
	}
}

// WithContext sets the context for the trainer
func (t *MLTrainer) WithContext(ctx context.Context) *MLTrainer {
	t.ctx = ctx

	return t
}

// InitModel initializes the neural network model
func (t *MLTrainer) InitModel() {
	util.DebugModule(definitions.DbgNeural,
		"action", "init_model_start",
	)

	// Default input size is 6 for the standard features
	inputSize := 6

	// Check if we have any training data with additional features
	trainingData, err := t.GetTrainingDataFromRedis(1)
	if err == nil && len(trainingData) > 0 && trainingData[0].Features != nil &&
		trainingData[0].Features.AdditionalFeatures != nil && len(trainingData[0].Features.AdditionalFeatures) > 0 {
		// Add the number of additional features to the input size
		inputSize += len(trainingData[0].Features.AdditionalFeatures)

		util.DebugModule(definitions.DbgNeural,
			"action", "init_model_with_additional_features",
			"additional_features_count", len(trainingData[0].Features.AdditionalFeatures),
			"total_input_size", inputSize,
		)
	}

	// Create a neural network with the appropriate number of input neurons,
	// 8 hidden neurons, and 1 output neuron (probability of brute force)
	t.model = NewNeuralNetwork(inputSize, 1)

	util.DebugModule(definitions.DbgNeural,
		"action", "init_model_complete",
		"input_size", inputSize,
		"hidden_size", t.model.hiddenSize,
		"output_size", 1,
	)
}

// LoadModelFromRedis loads a previously trained model from Redis
func (t *MLTrainer) LoadModelFromRedis() error {
	return t.LoadModelFromRedisWithKey(getMLRedisKeyPrefix() + "model")
}

// LoadModelFromRedisWithKey loads a previously trained model from Redis using the specified key
func (t *MLTrainer) LoadModelFromRedisWithKey(key string) error {
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
		LearningRate       float64   `json:"learning_rate"`
		ActivationFunction string    `json:"activation_function"`
	}

	if err := json.Unmarshal(jsonData, &modelData); err != nil {
		return fmt.Errorf("failed to deserialize model: %w", err)
	}

	// Get activation function from config or use default if not in the model data
	activationFunction := modelData.ActivationFunction
	if activationFunction == "" {
		// For backward compatibility with models saved before this change
		activationFunction = config.GetFile().GetBruteForce().GetNeuralNetwork().ActivationFunction
		if activationFunction == "" {
			activationFunction = "sigmoid" // Default to sigmoid if not specified
		}
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "load_model_parsed",
		"key", key,
		"input_size", modelData.InputSize,
		"hidden_size", modelData.HiddenSize,
		"output_size", modelData.OutputSize,
		"weights_count", len(modelData.Weights),
		"activation_function", activationFunction,
	)

	// Create a new neural network with the loaded parameters
	nn := &NeuralNetwork{
		inputSize:          modelData.InputSize,
		hiddenSize:         modelData.HiddenSize,
		outputSize:         modelData.OutputSize,
		weights:            modelData.Weights,
		learningRate:       modelData.LearningRate,
		activationFunction: activationFunction,
	}

	// Replace the current model
	t.model = nn

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Model loaded from Redis successfully (key: %s)", key),
	)

	return nil
}

// SaveModelToRedis saves the trained neural network model to Redis
func (t *MLTrainer) SaveModelToRedis() error {
	return t.SaveModelToRedisWithKey(getMLRedisKeyPrefix() + "model")
}

// SaveModelToRedisWithKey saves the trained neural network model to Redis using the specified key
func (t *MLTrainer) SaveModelToRedisWithKey(key string) error {
	if t.model == nil {
		return fmt.Errorf("no model to save")
	}

	// Create a serializable representation of the model
	modelData := struct {
		InputSize          int       `json:"input_size"`
		HiddenSize         int       `json:"hidden_size"`
		OutputSize         int       `json:"output_size"`
		Weights            []float64 `json:"weights"`
		LearningRate       float64   `json:"learning_rate"`
		ActivationFunction string    `json:"activation_function"`
	}{
		InputSize:          t.model.inputSize,
		HiddenSize:         t.model.hiddenSize,
		OutputSize:         t.model.outputSize,
		Weights:            t.model.weights,
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
		"activation_function", modelData.ActivationFunction,
	)

	// Serialize the model to JSON
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

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Model saved to Redis successfully (key: %s)", key),
	)

	return nil
}

// GetTrainingDataFromRedis retrieves the stored training data from Redis
// with balanced ratio of successful and failed login attempts
func (t *MLTrainer) GetTrainingDataFromRedis(maxSamples int) ([]TrainingData, error) {
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
func (t *MLTrainer) PrepareTrainingData(data []TrainingData) ([][]float64, [][]float64) {
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

				featureVector = append(featureVector, floatValue)

				util.DebugModule(definitions.DbgNeural,
					"action", "prepare_training_data_additional_feature",
					"key", key,
					"value", value,
					"float_value", floatValue,
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
func (t *MLTrainer) TrainWithStoredData(maxSamples int, epochs int) error {
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

	// Set the modelTrained flag if we have enough data
	// We consider the model trained if we have at least 100 samples
	if len(trainingData) >= 100 {
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
	}

	return nil
}

// GetModel returns the trained neural network model
func (t *MLTrainer) GetModel() *NeuralNetwork {
	return t.model
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
			"guid", guid,
		)

		return true
	}

	// Check if the IP is in the soft whitelist
	if config.GetFile().GetBruteForce().HasSoftWhitelist() {
		if util.IsSoftWhitelisted(username, clientIP, guid, config.GetFile().GetBruteForce().SoftWhitelist) {
			util.DebugModule(
				definitions.DbgNeural,
				"action", "ignore_ip_for_ml_training",
				"reason", "soft_whitelisted",
				"client_ip", clientIP,
				"username", username,
				"guid", guid,
			)

			return true
		}
	}

	// Check if the IP is in the IP whitelist
	if len(config.GetFile().GetBruteForce().IPWhitelist) > 0 {
		if util.IsInNetwork(config.GetFile().GetBruteForce().IPWhitelist, guid, clientIP) {
			util.DebugModule(
				definitions.DbgNeural,
				"action", "ignore_ip_for_ml_training",
				"reason", "ip_whitelisted",
				"client_ip", clientIP,
				"guid", guid,
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
	configMaxRecords := config.GetFile().GetBruteForce().GetNeuralNetwork().GetMaxTrainingRecords()
	if configMaxRecords > 0 {
		maxRecords = int64(configMaxRecords)
	}

	// Trim the list to keep only the last maxRecords entries
	err = rediscli.GetClient().GetWriteHandle().LTrim(ctx, key, 0, maxRecords-1).Err()
	if err != nil {
		return err
	}

	return nil
}

// Global variables for the ML system
var (
	// Global model trainer
	globalTrainer *MLTrainer

	// RWMutex to protect access to globalTrainer
	globalTrainerMutex sync.RWMutex

	// Channel to signal training goroutine to stop
	stopTrainingChan chan struct{}

	// Initialization synchronization
	initOnce sync.Once

	// Mutex for thread-safe shutdown
	shutdownMutex sync.Mutex

	// Flag to track if the scheduler is running
	schedulerStarted bool

	// Flag to track if the model has been trained with real data
	modelTrained bool

	// Mutex to protect access to modelTrained flag
	modelTrainedMutex sync.RWMutex
)

// InitMLSystem initializes the ML system without requiring request-specific parameters
// This should be called during application startup
// It will only initialize the ML system if the experimental_ml environment variable is set
func InitMLSystem(ctx context.Context) error {
	// Check if experimental ML is enabled
	if !config.GetEnvironment().GetExperimentalML() {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "ML system initialization skipped: experimental_ml is not enabled",
		)

		return nil
	}

	var err error

	initOnce.Do(func() {
		// Initialize modelTrained flag to false
		modelTrainedMutex.Lock()
		modelTrained = false
		modelTrainedMutex.Unlock()

		// Create a new trainer
		trainer := NewMLTrainer().WithContext(ctx)

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

		// Start scheduled training
		stopChan := make(chan struct{})
		stopTrainingChan = stopChan

		go func() {
			ticker := time.NewTicker(12 * time.Hour) // Train once twice per day
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				case <-ticker.C:
					level.Info(log.Logger).Log(
						definitions.LogKeyMsg, "Starting scheduled model training",
					)

					// Acquire write lock before training
					globalTrainerMutex.RLock()
					localTrainer := globalTrainer
					globalTrainerMutex.RUnlock()

					// Train with the last 5000 samples for 50 epochs
					if trainErr := localTrainer.TrainWithStoredData(5000, 50); trainErr != nil {
						level.Error(log.Logger).Log(
							definitions.LogKeyMsg, fmt.Sprintf("Scheduled training failed: %v", trainErr),
						)

						continue
					}

					// Save the trained model to Redis
					if saveErr := localTrainer.SaveModelToRedis(); saveErr != nil {
						level.Error(log.Logger).Log(
							definitions.LogKeyMsg, fmt.Sprintf("Failed to save model to Redis: %v", saveErr),
						)
					}
				}
			}
		}()

		schedulerStarted = true

		// Acquire write lock before setting globalTrainer
		globalTrainerMutex.Lock()
		globalTrainer = trainer
		globalTrainerMutex.Unlock()

		util.DebugModule(definitions.DbgNeural,
			"action", "init_ml_system_complete",
			"scheduler_started", schedulerStarted,
		)

		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Started ML model training scheduler",
		)
	})

	return err
}

// ShutdownMLSystem properly cleans up the ML system
// This should be called during application shutdown
func ShutdownMLSystem() {
	shutdownMutex.Lock()

	defer shutdownMutex.Unlock()

	if schedulerStarted && stopTrainingChan != nil {
		util.DebugModule(definitions.DbgNeural,
			"action", "shutdown_ml_system_stop_scheduler",
			"scheduler_started", schedulerStarted,
		)

		close(stopTrainingChan)

		schedulerStarted = false

		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Stopped ML model training scheduler",
		)
	} else {
		util.DebugModule(definitions.DbgNeural,
			"action", "shutdown_ml_system_no_scheduler",
			"scheduler_started", schedulerStarted,
			"stop_channel_nil", stopTrainingChan == nil,
		)
	}

	// Clear global variables
	globalTrainerMutex.Lock()
	globalTrainer = nil
	globalTrainerMutex.Unlock()

	stopTrainingChan = nil
}

// BruteForceMLDetector implements machine learning based brute force detection
type BruteForceMLDetector struct {
	ctx                context.Context
	guid               string
	clientIP           string
	username           string
	model              *NeuralNetwork
	additionalFeatures map[string]any
}

// getMLRedisKeyPrefix returns the Redis key prefix for ML models, including the instance name
func getMLRedisKeyPrefix() string {
	instanceName := config.GetFile().GetServer().GetInstanceName()

	return config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:" + instanceName + ":trained:"
}

// GetAdditionalFeaturesRedisKey returns the Redis key for additional features
func GetAdditionalFeaturesRedisKey() string {
	return getMLRedisKeyPrefix() + "additional_features"
}

// getModelTrainedRedisKey returns the Redis key for the model trained flag
func getModelTrainedRedisKey() string {
	return getMLRedisKeyPrefix() + "model_trained"
}

// SaveAdditionalFeaturesToRedis saves a model with additional features to a separate Redis key
func (t *MLTrainer) SaveAdditionalFeaturesToRedis() error {
	return t.SaveModelToRedisWithKey(GetAdditionalFeaturesRedisKey())
}

// LoadAdditionalFeaturesFromRedis loads a model with additional features from a separate Redis key
func (t *MLTrainer) LoadAdditionalFeaturesFromRedis() error {
	return t.LoadModelFromRedisWithKey(GetAdditionalFeaturesRedisKey())
}

// SaveModelTrainedFlagToRedis saves the model trained flag to Redis
func SaveModelTrainedFlagToRedis(ctx context.Context) error {
	modelTrainedMutex.RLock()
	isModelTrained := modelTrained
	modelTrainedMutex.RUnlock()

	key := getModelTrainedRedisKey()
	value := "0"
	if isModelTrained {
		value = "1"
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	err := rediscli.GetClient().GetWriteHandle().Set(
		ctx,
		key,
		value,
		0, // No expiration
	).Err()

	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to save model trained flag to Redis: %v", err),
		)
		return err
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "save_model_trained_flag",
		"model_trained", isModelTrained,
	)

	return nil
}

// LoadModelTrainedFlagFromRedis loads the model trained flag from Redis
func LoadModelTrainedFlagFromRedis(ctx context.Context) error {
	key := getModelTrainedRedisKey()

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	val, err := rediscli.GetClient().GetReadHandle().Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Key doesn't exist, model is not trained
			modelTrainedMutex.Lock()
			modelTrained = false
			modelTrainedMutex.Unlock()
			return nil
		}
		return err
	}

	isModelTrained := val == "1"
	modelTrainedMutex.Lock()
	modelTrained = isModelTrained
	modelTrainedMutex.Unlock()

	util.DebugModule(definitions.DbgNeural,
		"action", "load_model_trained_flag",
		"model_trained", isModelTrained,
	)

	return nil
}

// SetAdditionalFeatures sets additional features for the detector
func (d *BruteForceMLDetector) SetAdditionalFeatures(features map[string]any) {
	// Check if we need to reinitialize the model due to new additional features
	if d.model != nil && features != nil && len(features) > 0 {
		// Calculate the expected input size based on standard features (6) plus additional features
		expectedInputSize := 6 + len(features)

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

				// Copy weights for existing connections where possible
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
				}

				// Update the global trainer's model
				globalTrainerMutex.Lock()
				if globalTrainer != nil {
					globalTrainer.model = newModel
				}
				globalTrainerMutex.Unlock()

				// Update this detector's model
				d.model = newModel

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

						if err := localTrainer.TrainWithStoredData(1000, 20); err != nil {
							level.Error(log.Logger).Log(
								definitions.LogKeyMsg, fmt.Sprintf("Failed to train model after reinitializing for additional features: %v", err),
							)
						} else {
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
					}()
				}
			}
		}
	}

	// Set the additional features
	d.additionalFeatures = features
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

	// Acquire read lock to get the model
	globalTrainerMutex.RLock()
	model := globalTrainer.GetModel()
	globalTrainerMutex.RUnlock()

	// Create a new detector for this request
	detector := &BruteForceMLDetector{
		ctx:                ctx,
		guid:               guid,
		clientIP:           clientIP,
		username:           username,
		model:              model,                // Use the globally trained model
		additionalFeatures: make(map[string]any), // Initialize empty additional features
	}

	util.DebugModule(definitions.DbgNeural,
		"action", "get_detector_complete",
		definitions.LogKeyGUID, guid,
		"model_nil", detector.model == nil,
	)

	return detector
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

			inputs = append(inputs, floatValue)

			util.DebugModule(definitions.DbgNeural,
				"action", "predict_additional_feature",
				"key", key,
				"value", value,
				"float_value", floatValue,
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

	// Determine if it's a brute force attack based on threshold
	threshold := 0.7 // Threshold can be adjusted
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

// Helper methods to interact with Redis for feature collection

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

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Increment the counter
	err := rediscli.GetClient().GetWriteHandle().Incr(d.ctx, key).Err()
	if err != nil {
		return err
	}

	// Set expiration to 1 hour if not already set
	err = rediscli.GetClient().GetWriteHandle().Expire(d.ctx, key, time.Hour).Err()
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
		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		err := rediscli.GetClient().GetWriteHandle().SAdd(d.ctx, key, d.username).Err()
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, d.guid,
				definitions.LogKeyMsg, fmt.Sprintf("Failed to add username to set: %v", err),
			)

			return 0, err
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		// Set expiration to 1 hour if not already set
		err = rediscli.GetClient().GetWriteHandle().Expire(d.ctx, key, time.Hour).Err()
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, d.guid,
				definitions.LogKeyMsg, fmt.Sprintf("Failed to set expiration on username set: %v", err),
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

func (d *BruteForceMLDetector) getLoginTimeKey() string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:login:time:" + d.clientIP
}

func (d *BruteForceMLDetector) getFailedAttemptsKey() string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:failed:attempts:" + d.clientIP
}
