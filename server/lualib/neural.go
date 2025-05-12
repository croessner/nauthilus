package lualib

import (
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/gin-gonic/gin"
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

// LoaderModNeural loads Lua functions for neural network integration and returns them as a Lua module.
func LoaderModNeural(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnAddAdditionalFeatures: AddAdditionalFeatures(ctx),
		})

		L.Push(mod)

		return 1
	}
}
