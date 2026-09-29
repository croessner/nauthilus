// Copyright (C) 2026 Christian Rößner
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

package auth

import "github.com/gin-gonic/gin"

// CallerRateLimiter is the per-client-IP HTTP rate limiter shared with the global rate middleware, used by
// backchannel caller authentication as a failure budget per client IP.
//
// Backchannel callers are a few fixed infrastructure addresses, so a per-IP limit on authenticated callers caps
// the whole mail platform. Routes behind backchannel caller authentication are therefore exempted from the global
// middleware. Only failed caller authentications consume tokens, and an address without tokens is rejected before
// its credentials are checked, so credential guessing stays bounded per address. The shared concurrency budget
// bounds authenticated callers.
type CallerRateLimiter interface {
	// ExemptRoute removes the route with method and route pattern path from the global rate middleware.
	ExemptRoute(method string, path string)

	// AbortIfExhausted answers 429 without consuming a token when the client IP of ctx has no budget left.
	AbortIfExhausted(ctx *gin.Context) bool

	// ChargeFailure consumes one token of the client IP of ctx for a failed caller authentication.
	ChargeFailure(ctx *gin.Context)
}
