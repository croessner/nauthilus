// Copyright (C) 2026 Christian Roessner
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

package core

import (
	"net/http"
	"sort"
	"strings"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/http/httpguts"
)

const (
	pluginResponseHeaderAuthStatus         = "Auth-Status"
	pluginResponseHeaderAuthorization      = "Authorization"
	pluginResponseHeaderConnection         = "Connection"
	pluginResponseHeaderCookie             = "Cookie"
	pluginResponseHeaderProxyAuthorization = "Proxy-Authorization"
	pluginResponseHeaderSetCookie          = "Set-Cookie"
)

var pluginResponseForbiddenHeaders = map[string]struct{}{
	pluginResponseHeaderAuthStatus:         {},
	pluginResponseHeaderAuthorization:      {},
	pluginResponseHeaderCookie:             {},
	"Proxy-Authenticate":                   {},
	pluginResponseHeaderProxyAuthorization: {},
	pluginResponseHeaderSetCookie:          {},
}

var pluginResponseHopByHopHeaders = map[string]struct{}{
	pluginResponseHeaderConnection: {},
	"Keep-Alive":                   {},
	"Te":                           {},
	"Trailer":                      {},
	"Transfer-Encoding":            {},
	"Upgrade":                      {},
}

type pluginResponseMutationApplier struct {
	secretHeaders map[string]struct{}
}

type pluginResponseHeaderSet struct {
	name   string
	values []string
}

// ApplyPluginResponseMutation applies safe plugin response mutations while the HTTP response is still mutable.
func (a *AuthState) ApplyPluginResponseMutation(ctx *gin.Context, mutation pluginapi.ResponseMutation) {
	if !a.canApplyPluginResponseMutation(ctx) {
		return
	}

	applier := pluginResponseMutationApplier{
		secretHeaders: pluginResponseSecretHeaders(a.Cfg()),
	}
	applier.apply(ctx, a, mutation)
}

// canApplyPluginResponseMutation reports whether the current response boundary can still accept headers.
func (a *AuthState) canApplyPluginResponseMutation(ctx *gin.Context) bool {
	if a == nil || ctx == nil || ctx.Writer == nil {
		return false
	}

	if a.Request.Service == definitions.ServGRPC {
		return false
	}

	if ctx.GetBool(definitions.CtxResponseWrittenKey) || ctx.Writer.Written() {
		return false
	}

	return true
}

// apply writes normalized header operations and optional status-message exposure.
func (a pluginResponseMutationApplier) apply(ctx *gin.Context, auth *AuthState, mutation pluginapi.ResponseMutation) {
	headers := ctx.Writer.Header()

	for _, name := range a.normalizedDeletes(mutation.Headers.Delete) {
		headers.Del(name)
	}

	for _, item := range a.normalizedSets(mutation.Headers.Set) {
		headers.Del(item.name)

		for _, value := range item.values {
			headers.Add(item.name, value)
		}
	}

	if mutation.StatusHeader && auth != nil && strings.TrimSpace(auth.Runtime.StatusMessage) != "" {
		headers.Set(pluginResponseHeaderAuthStatus, auth.Runtime.StatusMessage)
	}
}

// normalizedDeletes returns sorted, allowed canonical header names.
func (a pluginResponseMutationApplier) normalizedDeletes(names []string) []string {
	if len(names) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		canonical, ok := a.canonicalHeaderName(name)
		if !ok {
			continue
		}

		seen[canonical] = struct{}{}
	}

	output := make([]string, 0, len(seen))
	for name := range seen {
		output = append(output, name)
	}

	sort.Strings(output)

	return output
}

// normalizedSets returns deterministic, allowed canonical header set operations.
func (a pluginResponseMutationApplier) normalizedSets(headers map[string][]string) []pluginResponseHeaderSet {
	if len(headers) == 0 {
		return nil
	}

	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	byCanonical := make(map[string][]string, len(headers))

	for _, key := range keys {
		canonical, ok := a.canonicalHeaderName(key)
		if !ok {
			continue
		}

		values := validPluginResponseHeaderValues(headers[key])
		if len(values) == 0 {
			continue
		}

		byCanonical[canonical] = values
	}

	names := make([]string, 0, len(byCanonical))
	for name := range byCanonical {
		names = append(names, name)
	}

	sort.Strings(names)

	output := make([]pluginResponseHeaderSet, 0, len(names))
	for _, name := range names {
		output = append(output, pluginResponseHeaderSet{
			name:   name,
			values: byCanonical[name],
		})
	}

	return output
}

// canonicalHeaderName validates and canonicalizes one plugin-controlled response header name.
func (a pluginResponseMutationApplier) canonicalHeaderName(name string) (string, bool) {
	canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
	if canonical == "" || !httpguts.ValidHeaderFieldName(canonical) {
		return "", false
	}

	if a.headerDenied(canonical) {
		return "", false
	}

	return canonical, true
}

// headerDenied reports whether a header is host-owned, hop-by-hop, or configured as secret-bearing.
func (a pluginResponseMutationApplier) headerDenied(header string) bool {
	if _, denied := pluginResponseForbiddenHeaders[header]; denied {
		return true
	}

	if _, denied := pluginResponseHopByHopHeaders[header]; denied {
		return true
	}

	_, denied := a.secretHeaders[header]

	return denied
}

// pluginResponseSecretHeaders returns configured request header names that must not be echoed by plugins.
func pluginResponseSecretHeaders(cfg config.File) map[string]struct{} {
	output := make(map[string]struct{}, 2)
	if cfg == nil || cfg.GetServer() == nil {
		return output
	}

	headers := cfg.GetServer().GetDefaultHTTPRequestHeader()
	for _, name := range []string{headers.GetPassword(), headers.GetPasswordEncoded()} {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" || !httpguts.ValidHeaderFieldName(canonical) {
			continue
		}

		output[canonical] = struct{}{}
	}

	return output
}

// validPluginResponseHeaderValues returns a defensive copy of valid response header values.
func validPluginResponseHeaderValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	output := make([]string, 0, len(values))
	for _, value := range values {
		if !httpguts.ValidHeaderFieldValue(value) {
			continue
		}

		output = append(output, value)
	}

	return output
}
