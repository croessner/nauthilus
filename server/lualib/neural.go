package lualib

import (
	"github.com/croessner/nauthilus/server/bruteforce/ml"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	lua "github.com/yuin/gopher-lua"
)

// AddAdditionalFeatures returns a Lua function that adds additional features to the AuthState for neural network processing.
// The function expects a Lua table as input, which will be converted to a map[string]any and stored in the lualib.Context.
// An optional second argument can be provided to specify the encoding type for string features:
// - "one-hot" (default): Uses one-hot encoding for string features
// - "embedding": Uses embedding encoding for string features
func AddAdditionalFeatures(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		// Check if we have a table as the first argument
		luaTable := L.CheckTable(1)
		if luaTable == nil {
			L.RaiseError("expected table as argument")

			return 0
		}

		// Check if we have an encoding type as the second argument
		encodingType := "one-hot" // Default to one-hot encoding
		if L.GetTop() >= 2 {
			if L.Get(2).Type() == lua.LTString {
				encodingTypeStr := L.ToString(2)
				if encodingTypeStr == "embedding" || encodingTypeStr == "one-hot" {
					encodingType = encodingTypeStr
				} else {
					L.RaiseError("invalid encoding type: %s (must be 'one-hot' or 'embedding')", encodingTypeStr)

					return 0
				}
			}
		}

		// Convert Lua table to Go map using the convert package
		features := make(map[string]any)
		// Store encoding type preferences
		encodingPreferences := make(map[string]string)

		luaTable.ForEach(func(key, value lua.LValue) {
			// Only string keys are supported
			if keyStr, ok := key.(lua.LString); ok {
				keyStrVal := string(keyStr)

				// Skip ClientIP and Username as per requirements
				if keyStrVal == "ClientIP" || keyStrVal == "client_ip" ||
					keyStrVal == "Username" || keyStrVal == "username" {
					// Skip these fields
					return
				}

				// Convert Lua value to Go value using convert package
				goValue := convert.LuaValueToGo(value)
				features[keyStrVal] = goValue

				// If the value is a string, store the encoding preference
				if _, isString := goValue.(string); isString {
					encodingPreferences[keyStrVal] = encodingType
				}
			}
		})

		// Check if there are existing features in the context
		var existingFeatures map[string]any
		var existingEncodingPreferences map[string]string

		if exists, ok := ctx.Get(definitions.CtxAdditionalFeaturesKey); ok {
			if existingMap, ok := exists.(map[string]any); ok {
				existingFeatures = existingMap
			}
		}

		if exists, ok := ctx.Get(definitions.CtxFeatureEncodingTypeKey); ok {
			if existingMap, ok := exists.(map[string]string); ok {
				existingEncodingPreferences = existingMap
			}
		}

		// If there are existing features, merge the new ones with them
		if existingFeatures != nil {
			// Create a new map to avoid modifying the existing one directly
			mergedFeatures := make(map[string]any, len(existingFeatures)+len(features))

			// Copy existing features
			for k, v := range existingFeatures {
				mergedFeatures[k] = v
			}

			// Add or overwrite with new features
			for k, v := range features {
				mergedFeatures[k] = v
			}

			// Store the merged features in the context
			ctx.Set(definitions.CtxAdditionalFeaturesKey, mergedFeatures)
		} else {
			// No existing features, just store the new ones
			ctx.Set(definitions.CtxAdditionalFeaturesKey, features)
		}

		// If there are existing encoding preferences, merge the new ones with them
		if existingEncodingPreferences != nil {
			// Create a new map to avoid modifying the existing one directly
			mergedPreferences := make(map[string]string, len(existingEncodingPreferences)+len(encodingPreferences))

			// Copy existing preferences
			for k, v := range existingEncodingPreferences {
				mergedPreferences[k] = v
			}

			// Add or overwrite with new preferences
			for k, v := range encodingPreferences {
				mergedPreferences[k] = v
			}

			// Store the merged preferences in the context
			ctx.Set(definitions.CtxFeatureEncodingTypeKey, mergedPreferences)
		} else {
			// No existing preferences, just store the new ones
			ctx.Set(definitions.CtxFeatureEncodingTypeKey, encodingPreferences)
		}

		return 0
	}
}

// GetAdditionalFeatures retrieves the additional features from the lualib.Context
// This function is called from core/bruteforce.go to get the additional features
func GetAdditionalFeatures(ctx *gin.Context) map[string]any {
	if ctx == nil {
		return nil
	}

	// Get the features from the lualib.Context
	if exists, ok := ctx.Get(definitions.CtxAdditionalFeaturesKey); ok {
		if features, ok := exists.(map[string]any); ok {
			return features
		}
	}

	return nil
}

// SetLearningMode returns a Lua function that allows toggling the learning mode on and off.
// The function accepts one parameter:
// - enabled (boolean): Whether to enable learning mode (true) or disable it (false)
// Returns a boolean indicating the new learning mode state (true if in learning mode, false otherwise)
// and an error message if the operation failed.
func SetLearningMode(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		// Check if we have an enabled parameter
		if L.GetTop() < 1 {
			L.RaiseError("missing required parameter: enabled")

			return 0
		}

		// Get the enabled parameter
		enabled := L.ToBool(1)

		// Check if Dry-Run is activated in the configuration
		if config.GetFile().GetBruteForce().GetNeuralNetwork().GetDryRun() {
			errMsg := "Cannot change learning mode when Dry-Run is activated in configuration"
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, errMsg,
			)

			// Push false and error message
			L.Push(lua.LBool(false))
			L.Push(lua.LString(errMsg))

			return 2
		}

		// Log the learning mode change request
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Learning mode change requested via Lua",
			"enabled", enabled,
		)

		// Set the learning mode
		newMode, err := ml.SetLearningMode(ctx, enabled)
		if err != nil {
			// Push false and error message
			L.Push(lua.LBool(newMode))
			L.Push(lua.LString(err.Error()))

			return 2
		}

		// Push the new mode and nil error
		L.Push(lua.LBool(newMode))
		L.Push(lua.LNil)

		return 2
	}
}

// GetLearningMode checks the system's current learning mode and pushes a boolean value to the Lua stack.
// Returns 1 as the number of return values being pushed to Lua.
func GetLearningMode(L *lua.LState) int {
	L.Push(lua.LBool(ml.GetLearningMode()))

	return 1
}

// TrainNeuralNetwork returns a Lua function that allows manual training of the neural network.
// The function accepts two optional parameters:
// - maxSamples (number): Maximum number of samples to use for training (default: 5000)
// - epochs (number): Number of epochs to train for (default: 50)
// Returns a boolean indicating success and an error message if training failed.
func TrainNeuralNetwork(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		// Default values
		maxSamples := 5000
		epochs := 50

		// Check if we have a maxSamples parameter
		if L.GetTop() >= 1 {
			if L.Get(1).Type() == lua.LTNumber {
				maxSamples = int(L.ToNumber(1))
				if maxSamples <= 0 {
					L.RaiseError("maxSamples must be a positive number")

					return 0
				}
			}
		}

		// Check if we have an epochs parameter
		if L.GetTop() >= 2 {
			if L.Get(2).Type() == lua.LTNumber {
				epochs = int(L.ToNumber(2))
				if epochs <= 0 {
					L.RaiseError("epochs must be a positive number")

					return 0
				}
			}
		}

		// Log the training request
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Manual neural network training requested via Lua",
			"maxSamples", maxSamples,
			"epochs", epochs,
		)

		// Create a bucket manager with ML capabilities
		// Use a dummy GUID and client IP since they're only used for logging
		guid := "lua-manual-training"
		clientIP := "127.0.0.1"

		// Create an ML bucket manager
		mlBucketManager, ok := ml.NewMLBucketManager(ctx, guid, clientIP).(*ml.MLBucketManager)
		if !ok {
			errMsg := "Failed to create ML bucket manager, experimental_ml might be disabled"
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, errMsg,
			)

			L.Push(lua.LBool(false))
			L.Push(lua.LString(errMsg))

			return 2
		}

		// Train the model
		err := mlBucketManager.TrainModel(maxSamples, epochs)
		if err != nil {
			// Push false and error message
			L.Push(lua.LBool(false))
			L.Push(lua.LString(err.Error()))

			return 2
		}

		// Push true and nil error
		L.Push(lua.LBool(true))
		L.Push(lua.LNil)

		return 2
	}
}

// LoaderModNeural loads Lua functions for neural network integration and returns them as a Lua module.
func LoaderModNeural(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		// Import the ProvideFeedback function from feedback.go
		provideFeedback := ProvideFeedback(ctx)

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnAddAdditionalFeatures: AddAdditionalFeatures(ctx),
			definitions.LuaFnTrainNeuralNetwork:    TrainNeuralNetwork(ctx),
			definitions.LuaFnSetLearningMode:       SetLearningMode(ctx),
			definitions.LuaFNGetLearningMode:       GetLearningMode,
			definitions.LuaFnProvideFeedback:       provideFeedback,
		})

		L.Push(mod)

		return 1
	}
}
