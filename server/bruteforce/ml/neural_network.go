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
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/util"

	"github.com/go-kit/log/level"
)

// NeuralNetwork is a simplified implementation of a neural network
type NeuralNetwork struct {
	inputSize          int
	hiddenSize         int
	outputSize         int
	weights            []float64  // In a real implementation, this would be a more complex structure
	hiddenBias         []float64  // Bias terms for hidden layer neurons
	outputBias         []float64  // Bias terms for output layer neurons
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
	var activationFunction string

	// Get neural network configuration, handling nil case
	// First check if BruteForce section exists
	bruteForce := config.GetFile().GetBruteForce()
	var nnConfig *config.NeuralNetwork

	if bruteForce == nil {
		// If BruteForce section is nil, use default values
		hiddenSize = 10
		activationFunction = "sigmoid"
	} else {
		// Get neural network configuration
		nnConfig = bruteForce.GetNeuralNetwork()

		// Set default hidden size if config is nil or hiddenNeurons is 0
		if nnConfig == nil || nnConfig.HiddenNeurons == 0 {
			hiddenSize = 10
		} else {
			hiddenSize = nnConfig.HiddenNeurons
		}

		// Get activation function from config or use default
		if nnConfig == nil || nnConfig.ActivationFunction == "" {
			activationFunction = "sigmoid" // Default to sigmoid if not specified
		} else {
			activationFunction = nnConfig.ActivationFunction
		}
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

	// Get learning rate from configuration, handling nil case
	var learningRate = 0.01 // Default learning rate
	if nnConfig != nil {
		learningRate = nnConfig.GetLearningRate()
	}

	// Create a new neural network with properly initialized weights and biases
	nn := &NeuralNetwork{
		inputSize:          inputSize,
		hiddenSize:         hiddenSize,
		outputSize:         outputSize,
		weights:            make([]float64, inputSize*hiddenSize+hiddenSize*outputSize),
		hiddenBias:         make([]float64, hiddenSize),
		outputBias:         make([]float64, outputSize),
		learningRate:       learningRate,
		rng:                rng,
		activationFunction: activationFunction,
	}

	// Initialize weights with small random values
	for i := range nn.weights {
		nn.weights[i] = (nn.rng.Float64() - 0.5) * 0.1
	}

	// Initialize bias terms with small random values
	for i := range nn.hiddenBias {
		nn.hiddenBias[i] = (nn.rng.Float64() - 0.5) * 0.1
	}

	for i := range nn.outputBias {
		nn.outputBias[i] = (nn.rng.Float64() - 0.5) * 0.1
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

	// Initialize weights and biases if they haven't been initialized properly
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

	// Initialize bias terms if they haven't been initialized properly
	if len(nn.hiddenBias) != nn.hiddenSize {
		util.DebugModule(definitions.DbgNeural,
			"action", "reinitialize_hidden_bias",
			"expected_size", nn.hiddenSize,
			"actual_size", len(nn.hiddenBias),
		)

		nn.hiddenBias = make([]float64, nn.hiddenSize)
		// Initialize hidden bias with small random values
		for i := range nn.hiddenBias {
			nn.hiddenBias[i] = (nn.rng.Float64() - 0.5) * 0.1
		}
	}

	if len(nn.outputBias) != nn.outputSize {
		util.DebugModule(definitions.DbgNeural,
			"action", "reinitialize_output_bias",
			"expected_size", nn.outputSize,
			"actual_size", len(nn.outputBias),
		)

		nn.outputBias = make([]float64, nn.outputSize)
		// Initialize output bias with small random values
		for i := range nn.outputBias {
			nn.outputBias[i] = (nn.rng.Float64() - 0.5) * 0.1
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

				// Add bias term
				if i < len(nn.hiddenBias) {
					sum += nn.hiddenBias[i]
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

				// Add bias term
				if i < len(nn.outputBias) {
					sum += nn.outputBias[i]
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

			// 3. Update weights and biases
			// Update weights between input and hidden layers
			for i := 0; i < nn.hiddenSize; i++ {
				for j := 0; j < nn.inputSize; j++ {
					weightIndex := i*nn.inputSize + j
					if weightIndex < len(nn.weights) {
						delta := nn.learningRate * hiddenDeltas[i] * inputFeatures[j]
						nn.weights[weightIndex] += delta
					}
				}

				// Update hidden layer bias
				if i < len(nn.hiddenBias) {
					delta := nn.learningRate * hiddenDeltas[i] // No input multiplication for bias
					nn.hiddenBias[i] += delta
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

				// Update output layer bias
				if i < len(nn.outputBias) {
					delta := nn.learningRate * outputDeltas[i] // No input multiplication for bias
					nn.outputBias[i] += delta
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

		// Add bias term
		if i < len(nn.hiddenBias) {
			sum += nn.hiddenBias[i]
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

		// Add bias term
		if i < len(nn.outputBias) {
			sum += nn.outputBias[i]
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
