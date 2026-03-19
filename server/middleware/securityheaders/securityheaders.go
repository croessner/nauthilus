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

package securityheaders

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

const (
	cspNoncePlaceholder = "{{nonce}}"
	nonceLengthBytes    = 18
)

// NonceGenerator defines the nonce generation behavior for CSP.
type NonceGenerator interface {
	Generate() (string, error)
}

// DefaultNonceGenerator generates cryptographically secure nonces.
type DefaultNonceGenerator struct{}

// Generate creates a base64 nonce suitable for CSP usage.
func (g DefaultNonceGenerator) Generate() (string, error) {
	buffer := make([]byte, nonceLengthBytes)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		return "", err
	}

	return base64.RawStdEncoding.EncodeToString(buffer), nil
}

// MiddlewareConfig configures the frontend security middleware dependencies.
type MiddlewareConfig struct {
	Config         config.File
	NonceGenerator NonceGenerator
}

// Middleware applies configurable security headers and CSP nonce handling.
type Middleware struct {
	cfg            config.File
	nonceGenerator NonceGenerator
}

// New creates a new security header middleware.
func New(cfg MiddlewareConfig) *Middleware {
	generator := cfg.NonceGenerator
	if generator == nil {
		generator = DefaultNonceGenerator{}
	}

	return &Middleware{
		cfg:            cfg.Config,
		nonceGenerator: generator,
	}
}

// Handler returns the gin middleware function.
func (m *Middleware) Handler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if m == nil || m.cfg == nil {
			ctx.Next()

			return
		}

		headers := m.cfg.GetServer().GetFrontend().GetSecurityHeaders()
		if headers == nil || !headers.IsEnabled() {
			ctx.Next()

			return
		}

		setHeader(ctx, "X-Content-Type-Options", headers.GetXContentTypeOptions())
		setHeader(ctx, "X-Frame-Options", headers.GetXFrameOptions())
		setHeader(ctx, "Referrer-Policy", headers.GetReferrerPolicy())
		setHeader(ctx, "Permissions-Policy", headers.GetPermissionsPolicy())
		setHeader(ctx, "Cross-Origin-Opener-Policy", headers.GetCrossOriginOpenerPolicy())
		setHeader(ctx, "Cross-Origin-Resource-Policy", headers.GetCrossOriginResourcePolicy())
		setHeader(ctx, "Cross-Origin-Embedder-Policy", headers.GetCrossOriginEmbedderPolicy())
		setHeader(ctx, "X-Permitted-Cross-Domain-Policies", headers.GetXPermittedCrossDomainPolicies())
		setHeader(ctx, "X-DNS-Prefetch-Control", headers.GetXDNSPrefetchControl())

		if isHTTPSRequest(ctx) {
			setHeader(ctx, "Strict-Transport-Security", headers.GetStrictTransportSecurity())
		}

		policy := strings.TrimSpace(headers.GetContentSecurityPolicy())
		if policy != "" {
			nonce, err := m.nonceGenerator.Generate()
			if err != nil {
				ctx.AbortWithStatus(http.StatusInternalServerError)

				return
			}

			ctx.Set(definitions.CtxCSPNonceKey, nonce)

			renderedPolicy := normalizePolicy(strings.ReplaceAll(policy, cspNoncePlaceholder, nonce))
			if renderedPolicy != "" {
				headerName := "Content-Security-Policy"
				if headers.IsContentSecurityPolicyReportOnly() {
					headerName = "Content-Security-Policy-Report-Only"
				}

				setHeader(ctx, headerName, renderedPolicy)
			}
		}

		ctx.Next()
	}
}

func setHeader(ctx *gin.Context, key string, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}

	ctx.Header(key, trimmed)
}

func isHTTPSRequest(ctx *gin.Context) bool {
	if ctx == nil || ctx.Request == nil {
		return false
	}

	if ctx.Request.TLS != nil {
		return true
	}

	return strings.EqualFold(strings.TrimSpace(ctx.GetHeader("X-Forwarded-Proto")), "https")
}

func normalizePolicy(policy string) string {
	parts := strings.Split(policy, ";")
	normalized := make([]string, 0, len(parts))

	for _, part := range parts {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}

		fields = normalizeDirective(fields)
		normalized = append(normalized, strings.Join(fields, " "))
	}

	return strings.Join(normalized, "; ")
}

func normalizeDirective(fields []string) []string {
	if len(fields) == 0 {
		return fields
	}

	directive := strings.ToLower(fields[0])
	if directive != "style-src" && directive != "style-src-elem" {
		return fields
	}

	hasUnsafeInline := slices.Contains(fields[1:], "'unsafe-inline'")

	if !hasUnsafeInline {
		return fields
	}

	normalized := make([]string, 0, len(fields))
	normalized = append(normalized, fields[0])

	for _, source := range fields[1:] {
		if strings.HasPrefix(strings.ToLower(source), "'nonce-") {
			continue
		}

		normalized = append(normalized, source)
	}

	return normalized
}

// NonceFromContext returns the request CSP nonce if present.
func NonceFromContext(ctx *gin.Context) string {
	if ctx == nil {
		return ""
	}

	value, exists := ctx.Get(definitions.CtxCSPNonceKey)
	if !exists {
		return ""
	}

	nonce, ok := value.(string)
	if !ok {
		return ""
	}

	return nonce
}

// NonceFromTemplateData resolves CSPNonce from the template data map.
func NonceFromTemplateData(data any) string {
	if data == nil {
		return ""
	}

	switch value := data.(type) {
	case map[string]any:
		nonce, _ := value["CSPNonce"].(string)
		return nonce
	case gin.H:
		nonce, _ := value["CSPNonce"].(string)
		return nonce
	default:
		return ""
	}
}
