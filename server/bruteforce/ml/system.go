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
	"net/http"
	"strings"
	"sync"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/util"
	jsoniter "github.com/json-iterator/go"

	"github.com/go-kit/log/level"
)

var (
	// Global model trainer
	globalTrainer *NeuralNetworkTrainer

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

	// modelDryRun determines if the model operations should execute in dry-run mode without making actual changes.
	modelDryRun bool

	// Flag to track if the model has been trained with real data
	modelTrained bool

	// Mutex to protect access to modelTrained flag
	modelTrainedMutex sync.RWMutex
)

var httpClient *http.Client

// json is a package-level variable for jsoniter with configuration for ML package (without decimal truncation)
var json = jsoniter.Config{
	EscapeHTML:                    true,
	SortMapKeys:                   true,
	ValidateJsonRawMessage:        true,
	MarshalFloatWith6Digits:       false, // No decimal truncation for ML package
	ObjectFieldMustBeSimpleString: true,
}.Froze()

// InitHTTPClient initializes and assigns a new HTTP client to the package-wide httpClient variable.
func InitHTTPClient() {
	httpClient = util.NewHTTPClient()
}

// InitMLSystem initializes the machine learning system, including training scheduler and model update subscribers.
// It performs initialization only once and skips setup if experimental ML is disabled in the environment configuration.
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
		// Create a new trainer
		trainer := NewMLTrainer().WithContext(ctx)

		// Get the canonical list of features from Redis
		canonicalFeatures, err := GetDynamicFeaturesFromRedis(ctx)
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to get canonical features from Redis during initialization: %v", err),
			)
			// Continue despite error - we'll still try to initialize the model
		} else {
			level.Info(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Loaded %d canonical features during ML system initialization", len(canonicalFeatures)),
				"features", strings.Join(canonicalFeatures, ", "),
			)
		}

		// Initialize model and trained flag
		// Note: initializeModelAndTrainedFlag now calls ResetModelToCanonicalFeatures internally
		// before loading the model, so we don't need to call it here
		initializeModelAndTrainedFlag(ctx, trainer)

		// Check for missed model update notifications
		// This ensures that instances that were down when notifications were published
		// can still process them when they come back up
		checkForMissedModelUpdates(ctx, trainer)

		// Start scheduled training
		stopChan := make(chan struct{})
		stopTrainingChan = stopChan

		// Start model update subscriber
		go modelUpdateSubscriber(ctx, stopChan)

		// Start learning mode update subscriber
		go learningModeUpdateSubscriber(ctx, stopChan)

		// Start scheduled training
		go scheduledTraining(ctx, stopChan)

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
