// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cookie

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

const canonicalSessionContextKey = "canonical_browser_session"

// CanonicalMode defines whether a route validates a fresh protocol request or continues bound state.
type CanonicalMode uint8

const (
	// CanonicalProtocolEntry may create a fresh anchor after purging a rejected or absent representation.
	CanonicalProtocolEntry CanonicalMode = iota + 1
	// CanonicalSelfServiceEntry may create a fresh anonymous anchor for the bounded MFA portal entry.
	CanonicalSelfServiceEntry
	// CanonicalContinuation requires an already valid canonical anchor and never reconstructs state.
	CanonicalContinuation
)

// CanonicalMiddleware composes the sole envelope runtime with an explicit route checkpoint.
func CanonicalMiddleware(runtime *CanonicalRuntime, mode CanonicalMode) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if runtime == nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)

			return
		}

		session, err := runtime.Open(ctx.Request.Context(), ctx.Request)
		if err == nil {
			ctx.Set(canonicalSessionContextKey, session)
			ctx.Next()

			return
		}

		runtime.PurgeBrowser(ctx.Writer)

		if !mayCreateCanonicalSession(mode, err) {
			ctx.AbortWithStatus(http.StatusConflict)

			return
		}

		session, err = runtime.Create(ctx.Request.Context(), ctx.Writer, false)
		if err != nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)

			return
		}

		ctx.Set(canonicalSessionContextKey, session)
		ctx.Next()
	}
}

// mayCreateCanonicalSession restricts fresh anchors to explicit entry modes and rejected envelopes.
func mayCreateCanonicalSession(mode CanonicalMode, err error) bool {
	if !errors.Is(err, ErrEnvelopeRejected) {
		return false
	}

	return mode == CanonicalProtocolEntry || mode == CanonicalSelfServiceEntry
}

// GetCanonicalSession returns the request-scoped typed browser session.
func GetCanonicalSession(ctx *gin.Context) *CanonicalSession {
	if ctx == nil {
		return nil
	}

	value, exists := ctx.Get(canonicalSessionContextKey)
	if !exists {
		return nil
	}

	session, _ := value.(*CanonicalSession)

	return session
}

// SetCanonicalSession replaces the request-scoped session after a durable handle rotation.
func SetCanonicalSession(ctx *gin.Context, session *CanonicalSession) {
	if ctx == nil || session == nil {
		return
	}

	ctx.Set(canonicalSessionContextKey, session)
}
