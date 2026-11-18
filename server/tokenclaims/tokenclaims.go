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

// Package tokenclaims holds transport-neutral predicates over validated access-token claims. Every resource-server
// adapter (the backchannel bearer middleware, the gRPC authority, the MCP endpoint) uses the same checks for token
// type, audience, and scope, so their acceptance rules cannot drift apart.
package tokenclaims

import (
	"encoding/json"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/golang-jwt/jwt/v5"
)

// scopeClaim is the space-delimited OAuth scope claim.
const scopeClaim = "scope"

// HasTokenType reports whether the claims carry exactly the given Nauthilus token type.
func HasTokenType(claims jwt.MapClaims, tokenType string) bool {
	if claims == nil || tokenType == "" {
		return false
	}

	actual, ok := claims[definitions.ClaimTokenType].(string)

	return ok && actual == tokenType
}

// HasAudience reports whether the normalized audience set contains audience.
func HasAudience(claims jwt.MapClaims, audience string) bool {
	if audience == "" {
		return false
	}

	audiences, ok := AudienceSet(claims)
	if !ok {
		return false
	}

	_, ok = audiences[audience]

	return ok
}

// HasExactAudienceSet reports whether the audience set equals expected exactly (no further audience, no duplicates
// of malformed values). An empty expectation never matches.
func HasExactAudienceSet(claims jwt.MapClaims, expected ...string) bool {
	if len(expected) == 0 {
		return false
	}

	audiences, ok := AudienceSet(claims)
	if !ok {
		return false
	}

	wanted := make(map[string]struct{}, len(expected))
	for _, audience := range expected {
		if audience == "" {
			return false
		}

		wanted[audience] = struct{}{}
	}

	if len(audiences) != len(wanted) {
		return false
	}

	for audience := range wanted {
		if _, present := audiences[audience]; !present {
			return false
		}
	}

	return true
}

// AudienceSet returns the audiences as a set. It fails for a missing claim and for any empty, padded, or invalid
// UTF-8 value, so a malformed audience can never be ignored into a match.
func AudienceSet(claims jwt.MapClaims) (map[string]struct{}, bool) {
	if claims == nil {
		return nil, false
	}

	audiences, err := claims.GetAudience()
	if err != nil || len(audiences) == 0 {
		return nil, false
	}

	result := make(map[string]struct{}, len(audiences))

	for _, audience := range audiences {
		if audience == "" || strings.TrimSpace(audience) != audience || !utf8.ValidString(audience) {
			return nil, false
		}

		result[audience] = struct{}{}
	}

	return result, true
}

// Scopes returns the values of the space-delimited scope claim; a missing or non-string claim yields none.
func Scopes(claims jwt.MapClaims) []string {
	if claims == nil {
		return nil
	}

	scopeValue, ok := claims[scopeClaim].(string)
	if !ok {
		return nil
	}

	return strings.Fields(scopeValue)
}

// HasScope reports whether the scope claim contains scope exactly.
func HasScope(claims jwt.MapClaims, scope string) bool {
	if claims == nil || scope == "" {
		return false
	}

	scopeValue, ok := claims[scopeClaim].(string)
	if !ok {
		return false
	}

	for candidate := range strings.SplitSeq(scopeValue, " ") {
		if candidate == scope {
			return true
		}
	}

	return false
}

// HasAnyScope reports whether the scope claim contains at least one of scopes.
func HasAnyScope(claims jwt.MapClaims, scopes ...string) bool {
	for _, scope := range scopes {
		if HasScope(claims, scope) {
			return true
		}
	}

	return false
}

// NumericDate reads a NumericDate claim (seconds since the epoch) from JWT claims (float64, json.Number) and from
// claims built from stored opaque-token sessions (int64, int). present is false for a missing claim; ok is false
// for a malformed, non-finite, or non-positive value.
func NumericDate(claims jwt.MapClaims, name string) (value time.Time, present bool, ok bool) {
	raw, present := claims[name]
	if !present {
		return time.Time{}, false, false
	}

	var seconds float64

	switch typed := raw.(type) {
	case float64:
		seconds = typed
	case int64:
		seconds = float64(typed)
	case int:
		seconds = float64(typed)
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return time.Time{}, true, false
		}

		seconds = parsed
	default:
		return time.Time{}, true, false
	}

	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 {
		return time.Time{}, true, false
	}

	whole, fraction := math.Modf(seconds)

	return time.Unix(int64(whole), int64(fraction*1e9)), true, true
}
