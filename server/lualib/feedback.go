package lualib

import (
	"time"

	"github.com/croessner/nauthilus/server/bruteforce/ml"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	lua "github.com/yuin/gopher-lua"
)

// ProvideFeedback returns a Lua function that allows providing feedback on predictions.
// The function accepts four parameters:
// - isBruteForce (boolean): Whether the login attempt was actually part of a brute force attack (true) or not (false)
// - requestId (string): The request ID of the login attempt to provide feedback for
// - clientIP (string): The client IP address of the login attempt
// - username (string): The username of the login attempt
// Returns a boolean indicating success and an error message if providing feedback failed.
func ProvideFeedback(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		// Check if we have the required parameters
		if L.GetTop() < 4 {
			L.RaiseError("missing required parameters: isBruteForce, requestId, clientIP, username")

			return 0
		}

		// Get the isBruteForce parameter
		isBruteForce := L.ToBool(1)

		// Get the requestId parameter
		requestId := L.ToString(2)
		if requestId == "" {
			L.RaiseError("requestId cannot be empty")

			return 0
		}

		// Get the clientIP parameter
		clientIP := L.ToString(3)
		if clientIP == "" {
			L.RaiseError("clientIP cannot be empty")

			return 0
		}

		// Get the username parameter
		username := L.ToString(4)
		if username == "" {
			L.RaiseError("username cannot be empty")

			return 0
		}

		// Log the feedback request
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "Feedback provided via Lua",
			"is_brute_force", isBruteForce,
			"request_id", requestId,
			"client_ip", clientIP,
			"username", username,
		)

		// Create a dummy set of features
		features := &ml.LoginFeatures{
			TimeBetweenAttempts:    0,
			FailedAttemptsLastHour: 0,
			DifferentUsernames:     0,
			DifferentPasswords:     0,
			TimeOfDay:              float64(time.Now().Hour()) / 24.0,
			SuspiciousNetwork:      0,
		}

		// Record the feedback
		err := ml.RecordFeedback(ctx, isBruteForce, features, clientIP, username, requestId)
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
