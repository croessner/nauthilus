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

// Package cors provides centralized CORS handling for HTTP routes.
package cors

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
)

// MiddlewareConfig configures centralized CORS middleware dependencies.
type MiddlewareConfig struct {
	Config config.File
}

// Middleware applies centralized CORS policy handling.
type Middleware struct {
	cfg config.File
}

// New creates a new centralized CORS middleware.
func New(cfg MiddlewareConfig) *Middleware {
	return &Middleware{
		cfg: cfg.Config,
	}
}

// Handler returns the gin middleware function.
func (m *Middleware) Handler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		policy, origin, proceed := m.resolveRequestPolicy(ctx)
		if !proceed {
			ctx.Next()

			return
		}

		if !m.applyOrigin(ctx, policy, origin) {
			return
		}

		if !isPreflight(ctx.Request) {
			ctx.Next()

			return
		}

		if !m.handlePreflight(ctx, policy) {
			ctx.AbortWithStatus(http.StatusForbidden)

			return
		}

		ctx.AbortWithStatus(http.StatusNoContent)
	}
}

// resolveRequestPolicy resolves the active CORS policy for the current request path
// and extracts the request Origin header. It returns proceed=false when CORS does
// not apply for the request.
func (m *Middleware) resolveRequestPolicy(ctx *gin.Context) (*config.CORSPolicy, string, bool) {
	if m == nil || m.cfg == nil || ctx == nil || ctx.Request == nil {
		return nil, "", false
	}

	corsCfg := m.cfg.GetServer().GetCORS()
	if corsCfg == nil || !corsCfg.IsEnabled() {
		return nil, "", false
	}

	policy, found := resolvePolicy(corsCfg.GetPolicies(), ctx.Request.URL.Path)
	if !found {
		return nil, "", false
	}

	origin := strings.TrimSpace(ctx.GetHeader("Origin"))
	if origin == "" {
		return nil, "", false
	}

	return policy, origin, true
}

// applyOrigin validates the incoming origin against the selected policy and sets
// origin-related response headers when allowed.
func (m *Middleware) applyOrigin(ctx *gin.Context, policy *config.CORSPolicy, origin string) bool {
	allowOrigin, originAllowed := resolveOrigin(origin, policy)
	if !originAllowed {
		if isPreflight(ctx.Request) {
			ctx.AbortWithStatus(http.StatusForbidden)

			return false
		}

		ctx.Next()

		return false
	}

	addVaryHeader(ctx.Writer.Header(), "Origin")
	setHeader(ctx, "Access-Control-Allow-Origin", allowOrigin)

	if policy.IsAllowCredentials() {
		setHeader(ctx, "Access-Control-Allow-Credentials", "true")
	}

	setHeader(ctx, "Access-Control-Expose-Headers", joinHeaderValues(policy.GetExposeHeaders()))

	return true
}

// handlePreflight validates requested method and headers for a preflight request
// and writes preflight-specific response headers.
func (m *Middleware) handlePreflight(ctx *gin.Context, policy *config.CORSPolicy) bool {
	requestedMethod := strings.TrimSpace(ctx.GetHeader("Access-Control-Request-Method"))
	if !isMethodAllowed(requestedMethod, policy.GetAllowMethods()) {
		return false
	}

	requestedHeaders := parseHeaderList(ctx.GetHeader("Access-Control-Request-Headers"))
	if !areHeadersAllowed(requestedHeaders, policy.GetAllowHeaders()) {
		return false
	}

	addVaryHeader(ctx.Writer.Header(), "Access-Control-Request-Method")
	addVaryHeader(ctx.Writer.Header(), "Access-Control-Request-Headers")

	setHeader(ctx, "Access-Control-Allow-Methods", joinHeaderValues(policy.GetAllowMethods()))
	setHeader(ctx, "Access-Control-Allow-Headers", joinHeaderValues(policy.GetAllowHeaders()))

	if maxAge := policy.GetMaxAge(); maxAge > 0 {
		setHeader(ctx, "Access-Control-Max-Age", strconv.FormatUint(uint64(maxAge), 10))
	}

	return true
}

// resolvePolicy returns the first policy that matches the request path.
func resolvePolicy(policies []config.CORSPolicy, path string) (*config.CORSPolicy, bool) {
	if len(policies) == 0 {
		return nil, false
	}

	requestPath := strings.TrimSpace(path)
	if requestPath == "" {
		requestPath = "/"
	}

	for index := range policies {
		policy := &policies[index]
		if policy.MatchesPath(requestPath) {
			return policy, true
		}
	}

	return nil, false
}

// resolveOrigin normalizes and validates the request origin against the configured
// allow list and returns the response value for Access-Control-Allow-Origin.
func resolveOrigin(origin string, policy *config.CORSPolicy) (string, bool) {
	requestOrigin, ok := canonicalOrigin(origin)
	if !ok {
		return "", false
	}

	allowCredentials := policy.IsAllowCredentials()
	for _, configuredOrigin := range policy.GetAllowOrigins() {
		trimmed := strings.TrimSpace(configuredOrigin)
		if trimmed == "" {
			continue
		}

		if trimmed == "*" {
			if allowCredentials {
				return requestOrigin, true
			}

			return "*", true
		}

		allowedOrigin, valid := canonicalOrigin(trimmed)
		if !valid {
			continue
		}

		if strings.EqualFold(allowedOrigin, requestOrigin) {
			return requestOrigin, true
		}
	}

	return "", false
}

// canonicalOrigin normalizes an origin string into "<scheme>://<host>" form.
func canonicalOrigin(origin string) (string, bool) {
	trimmed := strings.TrimSpace(origin)
	if trimmed == "" {
		return "", false
	}

	if strings.EqualFold(trimmed, "null") {
		return "null", true
	}

	parsedOrigin, err := url.Parse(trimmed)
	if err != nil || parsedOrigin == nil {
		return "", false
	}

	if parsedOrigin.Scheme == "" || parsedOrigin.Host == "" || parsedOrigin.User != nil {
		return "", false
	}

	return strings.ToLower(parsedOrigin.Scheme) + "://" + strings.ToLower(parsedOrigin.Host), true
}

// isPreflight reports whether the request is a CORS preflight request.
func isPreflight(request *http.Request) bool {
	if request == nil || !strings.EqualFold(request.Method, http.MethodOptions) {
		return false
	}

	if strings.TrimSpace(request.Header.Get("Origin")) == "" {
		return false
	}

	return strings.TrimSpace(request.Header.Get("Access-Control-Request-Method")) != ""
}

// isMethodAllowed validates the requested preflight method against allowed methods.
func isMethodAllowed(requestedMethod string, allowedMethods []string) bool {
	trimmedMethod := strings.TrimSpace(requestedMethod)
	if trimmedMethod == "" {
		return false
	}

	if len(allowedMethods) == 0 {
		return true
	}

	for _, method := range allowedMethods {
		trimmed := strings.TrimSpace(method)
		if trimmed == "" {
			continue
		}

		if trimmed == "*" || strings.EqualFold(trimmed, trimmedMethod) {
			return true
		}
	}

	return false
}

// areHeadersAllowed validates requested preflight headers against allowed headers.
func areHeadersAllowed(requestedHeaders []string, allowedHeaders []string) bool {
	if len(requestedHeaders) == 0 {
		return true
	}

	if len(allowedHeaders) == 0 {
		return true
	}

	normalizedAllowed := make([]string, 0, len(allowedHeaders))
	for _, header := range allowedHeaders {
		trimmed := strings.TrimSpace(header)
		if trimmed == "" {
			continue
		}

		normalizedAllowed = append(normalizedAllowed, strings.ToLower(trimmed))
	}

	if slices.Contains(normalizedAllowed, "*") {
		return true
	}

	for _, requested := range requestedHeaders {
		if !slices.Contains(normalizedAllowed, strings.ToLower(requested)) {
			return false
		}
	}

	return true
}

// parseHeaderList parses a comma-separated header list and removes duplicates.
func parseHeaderList(values string) []string {
	parts := strings.Split(values, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))

	for _, value := range parts {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		key := strings.ToLower(trimmed)
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		result = append(result, trimmed)
	}

	return result
}

// joinHeaderValues joins header values as a canonical comma-separated list.
func joinHeaderValues(values []string) string {
	if len(values) == 0 {
		return ""
	}

	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		key := strings.ToLower(trimmed)
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		result = append(result, trimmed)
	}

	return strings.Join(result, ", ")
}

// addVaryHeader appends a token to the Vary header if not already present.
func addVaryHeader(headers http.Header, value string) {
	trimmed := strings.TrimSpace(value)
	if headers == nil || trimmed == "" {
		return
	}

	current := headers.Values("Vary")
	for _, headerValue := range current {
		for part := range strings.SplitSeq(headerValue, ",") {
			if strings.EqualFold(strings.TrimSpace(part), trimmed) {
				return
			}
		}
	}

	headers.Add("Vary", trimmed)
}

// setHeader sets a header value when the value is non-empty.
func setHeader(ctx *gin.Context, key string, value string) {
	trimmed := strings.TrimSpace(value)
	if ctx == nil || trimmed == "" {
		return
	}

	ctx.Header(key, trimmed)
}
