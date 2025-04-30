package ml

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

// setupTestConfig initializes the configuration for testing
func setupTestConfig() {
	feature := config.Feature{}
	feature.Set("brute_force")

	backend := config.Backend{}
	backend.Set("cache")

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(&config.FileSettings{
		Server: &config.ServerSection{
			Features: []*config.Feature{&feature},
			Backends: []*config.Backend{&backend},
			Redis: config.Redis{
				Prefix: "nauthilus:",
			},
		},
		BruteForce: &config.BruteForceSection{
			NeuralNetwork: config.NeuralNetwork{
				HiddenNeurons:      10,
				ActivationFunction: "sigmoid",
			},
		},
	})

	log.SetupLogging(definitions.LogLevelNone, false, false, "test")
}

func TestNeuralNetwork_Train(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Create a neural network with 6 input neurons, 1 output neuron, and a fixed seed for reproducibility
	// Using a fixed seed ensures consistent test results across different environments
	nn := NewNeuralNetworkWithSeed(6, 1, 12345)

	// Create sample training data with more distinct patterns
	features := [][]float64{
		{0.1, 0.1, 0.1, 0.1, 0.1, 0.1}, // Sample 1 - Legitimate login (all low values)
		{0.9, 0.9, 0.9, 0.9, 0.9, 0.9}, // Sample 2 - Brute force attempt (all high values)
	}

	labels := [][]float64{
		{1.0}, // Legitimate login
		{0.0}, // Brute force attempt
	}

	// Train the neural network with more epochs to ensure convergence
	// Increased from 2000 to 5000 to ensure more reliable convergence
	nn.Train(features, labels, 5000)

	// Test prediction
	prediction := nn.FeedForward(features[0])
	assert.Len(t, prediction, 1, "Prediction should have 1 output")
	assert.True(t, prediction[0] > 0.5, "Prediction for legitimate login should be > 0.5")

	prediction = nn.FeedForward(features[1])
	assert.Len(t, prediction, 1, "Prediction should have 1 output")
	assert.True(t, prediction[0] < 0.5, "Prediction for brute force attempt should be < 0.5")
}

func TestMLTrainer_LoadSaveModel(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Create a Redis mock
	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}

	// Inject the mock client
	rediscli.NewTestClient(db)

	// Create a context
	ctx := context.Background()

	// Create an ML trainer
	trainer := NewMLTrainer().WithContext(ctx)

	// Initialize the model
	trainer.InitModel()

	// Set up expectations for SaveModelToRedis
	// The model is saved as a JSON string using SET
	// Use a matcher that accepts any string for the model data
	mock.Regexp().ExpectSet("nauthilus:ml:trained:model", `.*`, 30*24*time.Hour).SetVal("OK")

	// Save the model
	err := trainer.SaveModelToRedis()
	assert.NoError(t, err, "SaveModelToRedis should not return an error")

	// Set up expectations for LoadModelFromRedis
	// The model is loaded as a JSON string using GET
	// Provide a valid JSON model structure for the test
	mock.ExpectGet("nauthilus:ml:trained:model").SetVal(`{"input_size":6,"hidden_size":10,"output_size":1,"weights":[0.1,0.2,0.3,0.4,0.5,0.6],"learning_rate":0.01,"activation_function":"sigmoid"}`)

	// Load the model
	err = trainer.LoadModelFromRedis()
	assert.NoError(t, err, "LoadModelFromRedis should not return an error")

	// Verify all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestMLTrainer_GetTrainingDataFromRedis(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Create a Redis mock
	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}

	// Inject the mock client
	rediscli.NewTestClient(db)

	// Create a context
	ctx := context.Background()

	// Create an ML trainer
	trainer := NewMLTrainer().WithContext(ctx)

	// Set up expectations for GetTrainingDataFromRedis
	// Expect LRANGE to return some sample data
	sampleData := []string{
		`{"success":true,"features":{"time_between_attempts":60,"failed_attempts_last_hour":0,"different_usernames":1,"different_passwords":1,"time_of_day":0.5,"suspicious_network":0},"time":"2023-01-01T12:00:00Z"}`,
		`{"success":false,"features":{"time_between_attempts":1,"failed_attempts_last_hour":5,"different_usernames":3,"different_passwords":5,"time_of_day":0.5,"suspicious_network":1},"time":"2023-01-01T12:01:00Z"}`,
	}
	mock.ExpectLRange("nauthilus:ml:training:data", 0, 29).SetVal(sampleData)

	// Get training data
	data, err := trainer.GetTrainingDataFromRedis(10)
	assert.NoError(t, err, "GetTrainingDataFromRedis should not return an error")
	assert.Len(t, data, 2, "Should return 2 training samples")

	// Check the success status of each sample
	successCount := 0
	failedCount := 0
	for _, sample := range data {
		if sample.Success {
			successCount++
		} else {
			failedCount++
		}
	}

	// We should have at least one successful and one unsuccessful sample
	assert.True(t, successCount > 0, "Should have at least one successful sample")
	assert.True(t, failedCount > 0, "Should have at least one unsuccessful sample")

	// Verify all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestMLTrainer_TrainWithStoredData(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Create a Redis mock
	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}

	// Inject the mock client
	rediscli.NewTestClient(db)

	// Create a context
	ctx := context.Background()

	// Create an ML trainer
	trainer := NewMLTrainer().WithContext(ctx)

	// Initialize the model
	trainer.InitModel()

	// Set up expectations for TrainWithStoredData
	// Expect LRANGE to return some sample data
	sampleData := []string{
		`{"success":true,"features":{"time_between_attempts":60,"failed_attempts_last_hour":0,"different_usernames":1,"different_passwords":1,"time_of_day":0.5,"suspicious_network":0},"time":"2023-01-01T12:00:00Z"}`,
		`{"success":false,"features":{"time_between_attempts":1,"failed_attempts_last_hour":5,"different_usernames":3,"different_passwords":5,"time_of_day":0.5,"suspicious_network":1},"time":"2023-01-01T12:01:00Z"}`,
	}
	mock.ExpectLRange("nauthilus:ml:training:data", 0, 29).SetVal(sampleData)

	// Train with stored data
	err := trainer.TrainWithStoredData(10, 5)
	assert.NoError(t, err, "TrainWithStoredData should not return an error")

	// Verify all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestRecordLoginResult(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Create a Redis mock
	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}

	// Inject the mock client
	rediscli.NewTestClient(db)

	// Create a context
	ctx := context.Background()

	// Create login features
	features := &LoginFeatures{
		TimeBetweenAttempts:    60,
		FailedAttemptsLastHour: 0,
		DifferentUsernames:     1,
		DifferentPasswords:     1,
		TimeOfDay:              0.5,
		SuspiciousNetwork:      0.0, // 0.0 for false
		AdditionalFeatures:     make(map[string]any),
	}

	// Set up expectations for RecordLoginResult
	// Expect LRANGE to check the current balance
	mock.ExpectLRange("nauthilus:ml:training:data", 0, 999).SetVal([]string{})
	// Expect LPUSH to add the training data
	// Use a regexp matcher to match any JSON string
	mock.Regexp().ExpectLPush("nauthilus:ml:training:data", `.*`).SetVal(1)
	// Expect LTRIM to keep the list at a manageable size
	mock.ExpectLTrim("nauthilus:ml:training:data", 0, 9999).SetVal("OK")

	// Record login result
	err := RecordLoginResult(ctx, true, features)
	assert.NoError(t, err, "RecordLoginResult should not return an error")

	// Verify all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestInitMLSystem(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Create a Redis mock
	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}

	// Inject the mock client
	rediscli.NewTestClient(db)

	// Create a context
	ctx := context.Background()

	// Set up expectations for InitMLSystem
	// Expect GET to try loading the model from Redis
	mock.ExpectGet("nauthilus:ml:trained:model").RedisNil()

	// Initialize ML system
	err := InitMLSystem(ctx)
	assert.NoError(t, err, "InitMLSystem should not return an error")

	// Verify all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestNormalizeInputs(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Test with various inputs
	inputs := []float64{
		3600, // TimeBetweenAttempts (max value)
		50,   // FailedAttemptsLastHour (half of max)
		10,   // DifferentUsernames (half of max)
		5,    // DifferentPasswords (quarter of max)
		0.75, // TimeOfDay (already normalized)
		1.0,  // SuspiciousNetwork (already normalized)
	}

	normalized := normalizeInputs(inputs)

	// Check that all values are between 0 and 1
	for i, val := range normalized {
		assert.True(t, val >= 0 && val <= 1, "Normalized value at index %d should be between 0 and 1, got %f", i, val)
	}

	// Check specific normalizations
	assert.Equal(t, 1.0, normalized[0], "TimeBetweenAttempts should be normalized to 1.0")
	assert.Equal(t, 0.5, normalized[1], "FailedAttemptsLastHour should be normalized to 0.5")
	assert.Equal(t, 0.5, normalized[2], "DifferentUsernames should be normalized to 0.5")
	assert.Equal(t, 0.25, normalized[3], "DifferentPasswords should be normalized to 0.25")
	assert.Equal(t, 0.75, normalized[4], "TimeOfDay should remain 0.75")
	assert.Equal(t, 1.0, normalized[5], "SuspiciousNetwork should remain 1.0")
}

func TestPrepareTrainingData(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Create sample training data
	data := []TrainingData{
		{
			Time:    time.Now(),
			Success: true,
			Features: &LoginFeatures{
				TimeBetweenAttempts:    60,
				FailedAttemptsLastHour: 0,
				DifferentUsernames:     1,
				DifferentPasswords:     1,
				TimeOfDay:              0.5,
				SuspiciousNetwork:      0.0, // 0.0 for false
				AdditionalFeatures:     map[string]any{"custom_feature": "value"},
			},
		},
		{
			Time:    time.Now(),
			Success: false,
			Features: &LoginFeatures{
				TimeBetweenAttempts:    1,
				FailedAttemptsLastHour: 5,
				DifferentUsernames:     3,
				DifferentPasswords:     5,
				TimeOfDay:              0.5,
				SuspiciousNetwork:      1.0, // 1.0 for true
				AdditionalFeatures:     map[string]any{"custom_feature": "value2"},
			},
		},
	}

	// Create an ML trainer
	trainer := NewMLTrainer().WithContext(context.Background())

	// Prepare training data
	features, labels := trainer.PrepareTrainingData(data)

	// Check results
	assert.Len(t, features, 2, "Should have 2 feature vectors")
	assert.Len(t, labels, 2, "Should have 2 label vectors")

	// Check feature dimensions
	assert.Len(t, features[0], 7, "Feature vector should have 7 elements (6 standard + 1 additional)")

	// Check labels
	assert.Equal(t, 1.0, labels[0][0], "First sample should be labeled as legitimate (1.0)")
	assert.Equal(t, 0.0, labels[1][0], "Second sample should be labeled as brute force (0.0)")
}

func TestBalanceTrainingData(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Create sample training data with imbalance
	successfulSamples := []TrainingData{
		{Success: true},
		{Success: true},
		{Success: true},
		{Success: true},
		{Success: true},
		{Success: true},
		{Success: true},
		{Success: true},
		{Success: true},
		{Success: true},
	}

	failedSamples := []TrainingData{
		{Success: false},
		{Success: false},
	}

	// Balance the data
	balanced := balanceTrainingData(successfulSamples, failedSamples, 10)

	// Check results
	assert.Len(t, balanced, 10, "Should have 10 samples total")

	// Count successful and failed samples
	successCount := 0
	failedCount := 0
	for _, sample := range balanced {
		if sample.Success {
			successCount++
		} else {
			failedCount++
		}
	}

	// Check balance
	// The balanceTrainingData function is designed to maintain a ratio between 20% and 80% for each class
	// In this case, with 10 successful samples and 2 failed samples, the function will use all 2 failed samples
	// and reduce the successful samples to maintain the ratio
	assert.True(t, successCount >= 2, "Should have at least 2 successful samples")
	assert.True(t, successCount <= 8, "Should have at most 8 successful samples")
	assert.True(t, failedCount >= 2, "Should have at least 2 failed samples")
	assert.True(t, failedCount <= 8, "Should have at most 8 failed samples")
	assert.Equal(t, 10, successCount+failedCount, "Should have 10 samples total")
}

func TestGetBruteForceMLDetector(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Create a context
	ctx := context.Background()

	// Get a detector
	detector := GetBruteForceMLDetector(ctx, "test-guid", "127.0.0.1", "testuser")

	// Check that the detector is not nil
	assert.NotNil(t, detector, "Detector should not be nil")

	// Check that the detector has the correct properties
	assert.Equal(t, "test-guid", detector.guid, "Detector should have the correct GUID")
	assert.Equal(t, "127.0.0.1", detector.clientIP, "Detector should have the correct client IP")
	assert.Equal(t, "testuser", detector.username, "Detector should have the correct username")
}

func TestBruteForceMLDetector_SetAdditionalFeatures(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Set environment variable to skip training during tests
	oldEnv := os.Getenv("NAUTHILUS_TESTING")
	os.Setenv("NAUTHILUS_TESTING", "1")
	defer os.Setenv("NAUTHILUS_TESTING", oldEnv)

	t.Run("Basic reinitialization", func(t *testing.T) {
		// Create a Redis mock
		db, mock := redismock.NewClientMock()
		if db == nil || mock == nil {
			t.Fatalf("Failed to create Redis mock client.")
		}

		// Inject the mock client
		rediscli.NewTestClient(db)

		// Set up expectations for LoadModelFromRedis - return nil to simulate no saved model
		mock.ExpectGet("nauthilus:ml:trained:model").RedisNil()

		// Create a detector with a model
		detector := &BruteForceMLDetector{
			guid:  "test-guid",
			ctx:   context.Background(),
			model: NewNeuralNetwork(6, 1), // Standard model with 6 input neurons
		}

		// Check initial input size
		assert.Equal(t, 6, detector.model.inputSize, "Initial model should have 6 input neurons")

		// Set additional features
		additionalFeatures := map[string]any{
			"custom_feature1": "value1",
			"custom_feature2": 42,
			"custom_feature3": true,
		}

		// Create a global trainer for the test
		originalGlobalTrainer := globalTrainer
		defer func() { globalTrainer = originalGlobalTrainer }() // Restore after test

		// Create a trainer with context to avoid nil pointer in goroutine
		globalTrainer = &MLTrainer{
			ctx:   context.Background(),
			model: detector.model,
		}

		// No need to set up expectations for TrainWithStoredData and SaveModelToRedis
		// since we're skipping training during tests

		// Set additional features - this should trigger model reinitialization
		detector.SetAdditionalFeatures(additionalFeatures)

		// Check that the additional features were set
		assert.Equal(t, additionalFeatures, detector.additionalFeatures, "Additional features should be set correctly")

		// Check that the model was reinitialized with the correct input size
		assert.Equal(t, 9, detector.model.inputSize, "Model should be reinitialized with 9 input neurons (6 standard + 3 additional)")

		// Check that the weights array has the correct size
		expectedWeightsSize := 9*detector.model.hiddenSize + detector.model.hiddenSize*detector.model.outputSize
		assert.Equal(t, expectedWeightsSize, len(detector.model.weights), "Weights array should have the correct size")

		// Test adding more features
		moreFeatures := map[string]any{
			"custom_feature1": "value1",
			"custom_feature2": 42,
			"custom_feature3": true,
			"custom_feature4": 3.14,
			"custom_feature5": "new_value",
		}

		// Set more features - this should trigger another model reinitialization
		detector.SetAdditionalFeatures(moreFeatures)

		// Check that the model was reinitialized with the correct input size
		assert.Equal(t, 11, detector.model.inputSize, "Model should be reinitialized with 11 input neurons (6 standard + 5 additional)")

		// Check that the weights array has the correct size
		expectedWeightsSize = 11*detector.model.hiddenSize + detector.model.hiddenSize*detector.model.outputSize
		assert.Equal(t, expectedWeightsSize, len(detector.model.weights), "Weights array should have the correct size")
	})

	t.Run("Using saved weights from Redis", func(t *testing.T) {
		// Create a Redis mock
		db, mock := redismock.NewClientMock()
		if db == nil || mock == nil {
			t.Fatalf("Failed to create Redis mock client.")
		}

		// Inject the mock client
		rediscli.NewTestClient(db)

		// Create a detector with a model
		detector := &BruteForceMLDetector{
			guid:  "test-guid",
			ctx:   context.Background(),
			model: NewNeuralNetworkWithSeed(6, 1, 12345), // Standard model with 6 input neurons and fixed seed
		}

		// Create a saved model with 9 input neurons (6 standard + 3 additional)
		savedModel := NewNeuralNetworkWithSeed(9, 1, 54321) // Different seed to get different weights

		// Create a serializable representation of the saved model
		modelData := struct {
			InputSize          int       `json:"input_size"`
			HiddenSize         int       `json:"hidden_size"`
			OutputSize         int       `json:"output_size"`
			Weights            []float64 `json:"weights"`
			LearningRate       float64   `json:"learning_rate"`
			ActivationFunction string    `json:"activation_function"`
		}{
			InputSize:          savedModel.inputSize,
			HiddenSize:         savedModel.hiddenSize,
			OutputSize:         savedModel.outputSize,
			Weights:            savedModel.weights,
			LearningRate:       savedModel.learningRate,
			ActivationFunction: savedModel.activationFunction,
		}

		// Serialize the model to JSON
		jsonData, err := json.Marshal(modelData)
		assert.NoError(t, err, "Failed to serialize model")

		// Set up expectations for LoadModelFromRedis
		mock.ExpectGet("nauthilus:ml:trained:model").SetVal(string(jsonData))

		// No need to set up expectations for TrainWithStoredData and SaveModelToRedis
		// since we're skipping training during tests

		// Create a global trainer for the test
		originalGlobalTrainer := globalTrainer
		defer func() { globalTrainer = originalGlobalTrainer }() // Restore after test

		globalTrainer = &MLTrainer{
			ctx:   context.Background(),
			model: detector.model,
		}

		// Remember the original weights for the first 6 input neurons
		originalWeights := make([]float64, len(detector.model.weights))
		copy(originalWeights, detector.model.weights)

		// Set additional features - this should trigger model reinitialization
		additionalFeatures := map[string]any{
			"custom_feature1": "value1",
			"custom_feature2": 42,
			"custom_feature3": true,
		}
		detector.SetAdditionalFeatures(additionalFeatures)

		// Check that the model was reinitialized with the correct input size
		assert.Equal(t, 9, detector.model.inputSize, "Model should be reinitialized with 9 input neurons (6 standard + 3 additional)")

		// Check that the weights for the first 6 input neurons were preserved
		for i := 0; i < detector.model.hiddenSize; i++ {
			for j := 0; j < 6; j++ {
				oldWeightIndex := i*6 + j
				newWeightIndex := i*9 + j
				assert.Equal(t, originalWeights[oldWeightIndex], detector.model.weights[newWeightIndex],
					"Weight for existing connection should be preserved")
			}
		}

		// Check that the weights for the new connections match the saved model
		for i := 0; i < detector.model.hiddenSize; i++ {
			for j := 6; j < 9; j++ {
				savedWeightIndex := i*9 + j
				newWeightIndex := i*9 + j
				assert.Equal(t, savedModel.weights[savedWeightIndex], detector.model.weights[newWeightIndex],
					"Weight for new connection should match saved model")
			}
		}

		// Verify all expectations were met
		assert.NoError(t, mock.ExpectationsWereMet(), "There were unfulfilled expectations")
	})
}

// TestNeuralNetwork_ActivationFunctions tests all activation functions and their derivatives
func TestNeuralNetwork_ActivationFunctions(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	testCases := []struct {
		name                string
		activationFunction  string
		input               float64
		expectedOutput      float64
		expectedDerivative  float64
		outputTolerance     float64
		derivativeTolerance float64
	}{
		{
			name:                "Sigmoid with positive input",
			activationFunction:  "sigmoid",
			input:               2.0,
			expectedOutput:      0.8807970779778823,  // 1 / (1 + e^-2)
			expectedDerivative:  0.10499358540350662, // sigmoid(2) * (1 - sigmoid(2))
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
		{
			name:                "Sigmoid with negative input",
			activationFunction:  "sigmoid",
			input:               -2.0,
			expectedOutput:      0.11920292202211755, // 1 / (1 + e^2)
			expectedDerivative:  0.10499358540350662, // sigmoid(-2) * (1 - sigmoid(-2))
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
		{
			name:                "Sigmoid with zero input",
			activationFunction:  "sigmoid",
			input:               0.0,
			expectedOutput:      0.5,  // 1 / (1 + e^0)
			expectedDerivative:  0.25, // sigmoid(0) * (1 - sigmoid(0))
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
		{
			name:                "Tanh with positive input",
			activationFunction:  "tanh",
			input:               2.0,
			expectedOutput:      0.9640275800758169,  // tanh(2)
			expectedDerivative:  0.07065082485316443, // 1 - tanh^2(2)
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
		{
			name:                "Tanh with negative input",
			activationFunction:  "tanh",
			input:               -2.0,
			expectedOutput:      -0.9640275800758169, // tanh(-2)
			expectedDerivative:  0.07065082485316443, // 1 - tanh^2(-2)
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
		{
			name:                "Tanh with zero input",
			activationFunction:  "tanh",
			input:               0.0,
			expectedOutput:      0.0, // tanh(0)
			expectedDerivative:  1.0, // 1 - tanh^2(0)
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
		{
			name:                "ReLU with positive input",
			activationFunction:  "relu",
			input:               2.0,
			expectedOutput:      2.0, // max(0, 2)
			expectedDerivative:  1.0, // input > 0 ? 1 : 0
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
		{
			name:                "ReLU with negative input",
			activationFunction:  "relu",
			input:               -2.0,
			expectedOutput:      0.0, // max(0, -2)
			expectedDerivative:  0.0, // input > 0 ? 1 : 0
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
		{
			name:                "ReLU with zero input",
			activationFunction:  "relu",
			input:               0.0,
			expectedOutput:      0.0, // max(0, 0)
			expectedDerivative:  0.0, // input > 0 ? 1 : 0
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
		{
			name:                "Leaky ReLU with positive input",
			activationFunction:  "leaky_relu",
			input:               2.0,
			expectedOutput:      2.0, // max(0.01*2, 2)
			expectedDerivative:  1.0, // input > 0 ? 1 : 0.01
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
		{
			name:                "Leaky ReLU with negative input",
			activationFunction:  "leaky_relu",
			input:               -2.0,
			expectedOutput:      -0.02, // 0.01 * -2
			expectedDerivative:  0.01,  // input > 0 ? 1 : 0.01
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
		{
			name:                "Leaky ReLU with zero input",
			activationFunction:  "leaky_relu",
			input:               0.0,
			expectedOutput:      0.0,  // max(0.01*0, 0)
			expectedDerivative:  0.01, // input > 0 ? 1 : 0.01
			outputTolerance:     0.0001,
			derivativeTolerance: 0.0001,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a neural network with the specified activation function
			nn := &NeuralNetwork{
				activationFunction: tc.activationFunction,
			}

			// Test activation function
			output := nn.activate(tc.input)
			assert.InDelta(t, tc.expectedOutput, output, tc.outputTolerance,
				"Activation function %s should return %f for input %f, got %f",
				tc.activationFunction, tc.expectedOutput, tc.input, output)

			// Test activation derivative
			derivative := nn.activateDerivative(tc.input)
			assert.InDelta(t, tc.expectedDerivative, derivative, tc.derivativeTolerance,
				"Activation derivative %s should return %f for input %f, got %f",
				tc.activationFunction, tc.expectedDerivative, tc.input, derivative)
		})
	}
}

// TestNeuralNetwork_FeedForwardEdgeCases tests edge cases for the FeedForward method
func TestNeuralNetwork_FeedForwardEdgeCases(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	t.Run("Input size mismatch", func(t *testing.T) {
		// Create a neural network with 6 input neurons and 1 output neuron
		nn := NewNeuralNetwork(6, 1)

		// Test with too few inputs
		inputs := []float64{0.1, 0.2, 0.3, 0.4, 0.5} // Only 5 inputs, but network expects 6
		outputs := nn.FeedForward(inputs)
		assert.Len(t, outputs, 1, "Should return a default output array of length 1")
		assert.Equal(t, 0.5, outputs[0], "Should return default value 0.5 for insufficient inputs")

		// Test with too many inputs - now the network should use the first 6 inputs and ignore the rest
		inputs = []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7} // 7 inputs, but network expects 6
		outputs = nn.FeedForward(inputs)
		assert.Len(t, outputs, 1, "Should return an output array of length 1")
		assert.NotEqual(t, 0.5, outputs[0], "Should not return default value 0.5 for extra inputs")

		// Test with empty inputs
		inputs = []float64{}
		outputs = nn.FeedForward(inputs)
		assert.Len(t, outputs, 1, "Should return a default output array of length 1")
		assert.Equal(t, 0.5, outputs[0], "Should return default value 0.5 for empty inputs")
	})

	t.Run("Extreme input values", func(t *testing.T) {
		// Create a neural network with 6 input neurons and 1 output neuron
		nn := NewNeuralNetwork(6, 1)

		// Test with very large positive values
		inputs := []float64{1e10, 1e10, 1e10, 1e10, 1e10, 1e10}
		outputs := nn.FeedForward(inputs)
		assert.Len(t, outputs, 1, "Should return an output array of length 1")
		assert.True(t, outputs[0] >= 0 && outputs[0] <= 1, "Output should be between 0 and 1 even with extreme inputs")

		// Test with very large negative values
		inputs = []float64{-1e10, -1e10, -1e10, -1e10, -1e10, -1e10}
		outputs = nn.FeedForward(inputs)
		assert.Len(t, outputs, 1, "Should return an output array of length 1")
		assert.True(t, outputs[0] >= 0 && outputs[0] <= 1, "Output should be between 0 and 1 even with extreme inputs")

		// Test with NaN values
		inputs = []float64{math.NaN(), math.NaN(), math.NaN(), math.NaN(), math.NaN(), math.NaN()}
		outputs = nn.FeedForward(inputs)
		assert.Len(t, outputs, 1, "Should return an output array of length 1")
		// Note: We can't directly check for NaN with assert.Equal, so we use math.IsNaN
		assert.True(t, math.IsNaN(outputs[0]) || (outputs[0] >= 0 && outputs[0] <= 1),
			"Output should handle NaN inputs gracefully")
	})
}

// TestBruteForceMLDetector_IsFromSuspiciousNetwork tests the isFromSuspiciousNetwork method
func TestBruteForceMLDetector_IsFromSuspiciousNetwork(t *testing.T) {
	// Set up test configuration
	setupTestConfig()

	// Create a Redis mock
	db, mock := redismock.NewClientMock()
	assert.NotNil(t, db, "Failed to create Redis mock client")
	assert.NotNil(t, mock, "Failed to create Redis mock")

	// Inject the mock client
	rediscli.NewTestClient(db)

	// Create a context
	ctx := context.Background()

	// Create a detector
	detector := GetBruteForceMLDetector(ctx, "test-guid", "127.0.0.1", "testuser")

	// Test when no blocklist URL is configured
	t.Run("No blocklist URL", func(t *testing.T) {
		// Save current env and restore after test
		oldEnv := os.Getenv("BLOCKLIST_URL")
		defer os.Setenv("BLOCKLIST_URL", oldEnv)

		// Clear the environment variable
		os.Setenv("BLOCKLIST_URL", "")

		suspicious, err := detector.isFromSuspiciousNetwork()
		assert.NoError(t, err, "isFromSuspiciousNetwork should not return an error when no blocklist URL is configured")
		assert.False(t, suspicious, "Should return false when no blocklist URL is configured")
	})

	// Test with a blocklist service that returns IP found
	t.Run("IP found in blocklist", func(t *testing.T) {
		// Save current env and restore after test
		oldEnv := os.Getenv("BLOCKLIST_URL")
		defer os.Setenv("BLOCKLIST_URL", oldEnv)

		// Create a test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check request method and headers
			assert.Equal(t, http.MethodPost, r.Method, "Should use POST method")
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"), "Should set Content-Type header")
			assert.Equal(t, "Nauthilus", r.Header.Get("User-Agent"), "Should set User-Agent header")

			// Parse request body
			var payload map[string]string
			err := json.NewDecoder(r.Body).Decode(&payload)
			assert.NoError(t, err, "Should be able to parse request body")
			assert.Equal(t, "127.0.0.1", payload["ip"], "Should send the correct IP")

			// Return a response indicating the IP was found
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := map[string]bool{"found": true}
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		// Set the blocklist URL to the test server
		os.Setenv("BLOCKLIST_URL", server.URL)

		// Save and restore the original HTTP client
		originalClient := httpClient
		defer func() { httpClient = originalClient }()

		// Use the default HTTP client for the test
		httpClient = http.DefaultClient

		suspicious, err := detector.isFromSuspiciousNetwork()
		assert.NoError(t, err, "isFromSuspiciousNetwork should not return an error")
		assert.True(t, suspicious, "Should return true when IP is found in blocklist")
	})

	// Test with a blocklist service that returns IP not found
	t.Run("IP not found in blocklist", func(t *testing.T) {
		// Save current env and restore after test
		oldEnv := os.Getenv("BLOCKLIST_URL")
		defer os.Setenv("BLOCKLIST_URL", oldEnv)

		// Create a test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return a response indicating the IP was not found
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := map[string]bool{"found": false}
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		// Set the blocklist URL to the test server
		os.Setenv("BLOCKLIST_URL", server.URL)

		// Save and restore the original HTTP client
		originalClient := httpClient
		defer func() { httpClient = originalClient }()

		// Use the default HTTP client for the test
		httpClient = http.DefaultClient

		suspicious, err := detector.isFromSuspiciousNetwork()
		assert.NoError(t, err, "isFromSuspiciousNetwork should not return an error")
		assert.False(t, suspicious, "Should return false when IP is not found in blocklist")
	})

	// Test with a blocklist service that returns an error
	t.Run("Blocklist service error", func(t *testing.T) {
		// Save current env and restore after test
		oldEnv := os.Getenv("BLOCKLIST_URL")
		defer os.Setenv("BLOCKLIST_URL", oldEnv)

		// Create a test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return an error response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := map[string]string{"error": "Service unavailable"}
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		// Set the blocklist URL to the test server
		os.Setenv("BLOCKLIST_URL", server.URL)

		// Save and restore the original HTTP client
		originalClient := httpClient
		defer func() { httpClient = originalClient }()

		// Use the default HTTP client for the test
		httpClient = http.DefaultClient

		suspicious, err := detector.isFromSuspiciousNetwork()
		assert.Error(t, err, "isFromSuspiciousNetwork should return an error")
		assert.False(t, suspicious, "Should return false when blocklist service returns an error")
	})
}
