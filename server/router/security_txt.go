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

package router

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
)

const securityTxtPath = "/.well-known/security.txt"

// WithSecurityTxt registers the RFC 9116 security.txt endpoint when enabled.
func (r *Router) WithSecurityTxt() *Router {
	securityTxt := r.Cfg.GetServer().GetSecurityTxt()
	if !securityTxt.IsEnabled() {
		return r
	}

	r.Engine.GET(securityTxtPath, func(ctx *gin.Context) {
		body := NewSecurityTxtRenderer(securityTxt).Render()

		ctx.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(body))
	})

	r.registerSecurityTxtFile(securityTxt.GetEncryptionURI(), securityTxt.GetEncryptionFile(), "application/pgp-keys")
	r.registerSecurityTxtFile(securityTxt.GetPolicyURI(), securityTxt.GetPolicyFile(), "text/markdown; charset=utf-8")

	return r
}

// SecurityTxtRenderer renders configured security.txt fields in RFC 9116 format.
type SecurityTxtRenderer struct {
	cfg *config.SecurityTxt
	now func() time.Time
}

// NewSecurityTxtRenderer creates a renderer for a security.txt configuration.
func NewSecurityTxtRenderer(cfg *config.SecurityTxt) SecurityTxtRenderer {
	return SecurityTxtRenderer{cfg: cfg, now: time.Now}
}

// Render returns the configured security.txt document.
func (r SecurityTxtRenderer) Render() string {
	if r.cfg == nil {
		return ""
	}

	var builder strings.Builder

	writeURIFields(&builder, "Contact", r.cfg.GetContacts())
	writeSingleTimeField(&builder, "Expires", r.expiresValue())
	writeURIFields(&builder, "Encryption", appendConfiguredURI(r.cfg.GetEncryption(), r.cfg.GetEncryptionURI()))
	writeURIFields(&builder, "Acknowledgments", r.cfg.GetAcknowledgments())
	writePreferredLanguages(&builder, r.cfg.GetPreferredLanguages())
	writeURIFields(&builder, "Canonical", r.cfg.GetCanonical())
	writeURIFields(&builder, "Policy", appendConfiguredURI(r.cfg.GetPolicy(), r.cfg.GetPolicyURI()))
	writeURIFields(&builder, "Hiring", r.cfg.GetHiring())

	return builder.String()
}

func (r SecurityTxtRenderer) expiresValue() string {
	expiresAfter := r.cfg.GetExpiresAfter()
	if expiresAfter <= 0 {
		return r.cfg.GetExpires()
	}

	now := r.now
	if now == nil {
		now = time.Now
	}

	return now().UTC().Add(expiresAfter).Format(time.RFC3339)
}

func (r *Router) registerSecurityTxtFile(publicURI string, filePath string, contentType string) {
	routePath := securityTxtRoutePath(publicURI)
	if routePath == "" || strings.TrimSpace(filePath) == "" {
		return
	}

	r.Engine.GET(routePath, func(ctx *gin.Context) {
		content, err := os.ReadFile(filePath)
		if err != nil {
			ctx.String(http.StatusNotFound, "404 - Page Not Found")

			return
		}

		ctx.Header("X-Content-Type-Options", "nosniff")
		ctx.Data(http.StatusOK, contentType, content)
	})
}

func securityTxtRoutePath(publicURI string) string {
	parsed, err := url.Parse(strings.TrimSpace(publicURI))
	if err != nil || parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") {
		return ""
	}

	return parsed.Path
}

func appendConfiguredURI(values []string, configuredURI string) []string {
	trimmed := strings.TrimSpace(configuredURI)
	if trimmed == "" {
		return values
	}

	return append(append([]string(nil), values...), trimmed)
}

func writeURIFields(builder *strings.Builder, field string, values []string) {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		builder.WriteString(field)
		builder.WriteString(": ")
		builder.WriteString(trimmed)
		builder.WriteByte('\n')
	}
}

func writeSingleTimeField(builder *strings.Builder, field string, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}

	if parsed, err := time.Parse(time.RFC3339, trimmed); err == nil {
		trimmed = parsed.UTC().Format(time.RFC3339)
	}

	builder.WriteString(field)
	builder.WriteString(": ")
	builder.WriteString(trimmed)
	builder.WriteByte('\n')
}

func writePreferredLanguages(builder *strings.Builder, values []string) {
	trimmedValues := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		trimmedValues = append(trimmedValues, trimmed)
	}

	if len(trimmedValues) == 0 {
		return
	}

	builder.WriteString("Preferred-Languages: ")
	builder.WriteString(strings.Join(trimmedValues, ", "))
	builder.WriteByte('\n')
}
