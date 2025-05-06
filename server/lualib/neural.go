package lualib

import (
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	lua "github.com/yuin/gopher-lua"
)

// AddAdditionalFeatures returns a Lua function that adds additional features to the AuthState for neural network processing.
// The function expects a Lua table as input, which will be converted to a map[string]any and stored in the lualib.Context.
func AddAdditionalFeatures(ctx *Context) lua.LGFunction {
	return func(L *lua.LState) int {
		// Check if we have a table as the first argument
		luaTable := L.CheckTable(1)
		if luaTable == nil {
			L.RaiseError("expected table as argument")

			return 0
		}

		// Convert Lua table to Go map using the convert package
		features := make(map[string]any)

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
			}
		})

		// Check if there are existing features in the context
		var existingFeatures map[string]any

		if existing := ctx.Get(definitions.CtxAdditionalFeaturesKey); existing != nil {
			if existingMap, ok := existing.(map[string]any); ok {
				existingFeatures = existingMap
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

		return 0
	}
}

// GetAdditionalFeatures retrieves the additional features from the lualib.Context
// This function is called from core/bruteforce.go to get the additional features
func GetAdditionalFeatures(ctx *Context) map[string]any {
	if ctx == nil {
		return nil
	}

	// Get the features from the lualib.Context
	if features, ok := ctx.Get(definitions.CtxAdditionalFeaturesKey).(map[string]any); ok {
		return features
	}

	return nil
}

// LoaderModNeural loads Lua functions for neural network integration and returns them as a Lua module.
func LoaderModNeural(ctx *Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnAddAdditionalFeatures: AddAdditionalFeatures(ctx),
		})

		L.Push(mod)

		return 1
	}
}
