package custom

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/middleware/oidcbearer"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http/httpguts"
)

const (
	nativeHookErrorField               = "error"
	nativeHookHeaderAuthorization      = "Authorization"
	nativeHookHeaderConnection         = "Connection"
	nativeHookHeaderCookie             = "Cookie"
	nativeHookHeaderCSP                = "Content-Security-Policy"
	nativeHookHeaderProxyAuthenticate  = "Proxy-Authenticate"
	nativeHookHeaderProxyAuthorization = "Proxy-Authorization"
	nativeHookHeaderSetCookie          = "Set-Cookie"
	nativeHookBodyTooLarge             = "hook request body too large"
)

var nativeHookHopByHopHeaders = map[string]struct{}{
	nativeHookHeaderConnection:         {},
	"Keep-Alive":                       {},
	nativeHookHeaderProxyAuthenticate:  {},
	nativeHookHeaderProxyAuthorization: {},
	"Te":                               {},
	"Trailer":                          {},
	"Transfer-Encoding":                {},
	"Upgrade":                          {},
}

var nativeHookForbiddenResponseHeaders = map[string]struct{}{
	"Auth-Status":                      {},
	nativeHookHeaderAuthorization:      {},
	nativeHookHeaderCookie:             {},
	nativeHookHeaderProxyAuthenticate:  {},
	nativeHookHeaderProxyAuthorization: {},
	nativeHookHeaderSetCookie:          {},
}

var nativeHookHostOwnedHeaders = map[string]struct{}{
	"Access-Control-Allow-Credentials":    {},
	"Access-Control-Allow-Headers":        {},
	"Access-Control-Allow-Methods":        {},
	"Access-Control-Allow-Origin":         {},
	"Access-Control-Expose-Headers":       {},
	"Access-Control-Max-Age":              {},
	"Alt-Svc":                             {},
	"Content-Length":                      {},
	nativeHookHeaderCSP:                   {},
	"Content-Security-Policy-Report-Only": {},
	"Cross-Origin-Embedder-Policy":        {},
	"Cross-Origin-Opener-Policy":          {},
	"Cross-Origin-Resource-Policy":        {},
	"Date":                                {},
	"Permissions-Policy":                  {},
	"Referrer-Policy":                     {},
	"Server":                              {},
	"Strict-Transport-Security":           {},
	"X-Content-Type-Options":              {},
	"X-Dns-Prefetch-Control":              {},
	"X-Frame-Options":                     {},
	"X-Permitted-Cross-Domain-Policies":   {},
}

// NativeHookRunner invokes one native plugin hook through the runtime boundary.
type NativeHookRunner interface {
	ServeHook(context.Context, string, pluginapi.HookRequest) (pluginapi.HookResponse, error)
}

// NativeHookRequestBuilder builds the public hook request after host validation.
type NativeHookRequestBuilder func(*gin.Context, config.File, pluginapi.HookDescriptor, NativeHookCaller, []byte) (pluginapi.HookRequest, error)

// NativeHookCaller contains authenticated caller metadata for request building.
type NativeHookCaller struct {
	Subject       string
	ClientID      string
	Authenticated bool
}

// NativeHook binds one registered plugin hook to the custom HTTP handler.
type NativeHook struct {
	Runner        NativeHookRunner
	BuildRequest  NativeHookRequestBuilder
	Descriptor    pluginapi.HookDescriptor
	QualifiedName string
	ModuleName    string
	ComponentName string
}

type nativeHookIndex struct {
	hooks           map[string]NativeHook
	aliases         map[string]string
	aliasTargets    map[string]string
	rejectedHooks   map[string]struct{}
	rejectedAliases map[string]struct{}
}

// newNativeHookIndex indexes valid native hook bindings by method and path.
func newNativeHookIndex(hooks []NativeHook) *nativeHookIndex {
	index := &nativeHookIndex{
		hooks:           make(map[string]NativeHook, len(hooks)),
		aliases:         make(map[string]string),
		aliasTargets:    make(map[string]string),
		rejectedHooks:   make(map[string]struct{}),
		rejectedAliases: make(map[string]struct{}),
	}

	for _, hook := range hooks {
		if hook.Runner == nil || hook.BuildRequest == nil || hook.QualifiedName == "" {
			continue
		}

		path := normalizeNativeHookPath(hook.Descriptor.Path)
		if path == "" || strings.TrimSpace(hook.Descriptor.Method) == "" {
			continue
		}

		hook.Descriptor.Path = path

		key := nativeHookKey(path, hook.Descriptor.Method)
		if !index.addHookBinding(key, hook) {
			continue
		}

		if alias := normalizeNativeHookPath(hook.Descriptor.Alias); alias != "" {
			index.addAliasBinding(nativeHookKey(alias, hook.Descriptor.Method), key, path)
		}
	}

	return index
}

// addHookBinding records one canonical binding and rejects duplicate keys.
func (i *nativeHookIndex) addHookBinding(key string, hook NativeHook) bool {
	if _, rejected := i.rejectedHooks[key]; rejected {
		return false
	}

	if _, exists := i.hooks[key]; exists {
		delete(i.hooks, key)
		i.rejectedHooks[key] = struct{}{}
		i.removeAliasesForHook(key)

		return false
	}

	i.hooks[key] = hook

	return true
}

// addAliasBinding records one alias binding and rejects duplicate alias keys.
func (i *nativeHookIndex) addAliasBinding(aliasKey string, canonicalKey string, canonicalPath string) {
	if _, rejected := i.rejectedAliases[aliasKey]; rejected {
		return
	}

	if _, exists := i.aliases[aliasKey]; exists {
		delete(i.aliases, aliasKey)
		delete(i.aliasTargets, aliasKey)
		i.rejectedAliases[aliasKey] = struct{}{}

		return
	}

	i.aliases[aliasKey] = canonicalPath
	i.aliasTargets[aliasKey] = canonicalKey
}

// removeAliasesForHook removes aliases that point at an ambiguous canonical hook.
func (i *nativeHookIndex) removeAliasesForHook(canonicalKey string) {
	for aliasKey, targetKey := range i.aliasTargets {
		if targetKey != canonicalKey {
			continue
		}

		delete(i.aliases, aliasKey)
		delete(i.aliasTargets, aliasKey)
		i.rejectedAliases[aliasKey] = struct{}{}
	}
}

// aliasMap returns a detached copy of native hook aliases.
func (i *nativeHookIndex) aliasMap() map[string]string {
	if i == nil || len(i.aliases) == 0 {
		return nil
	}

	aliases := make(map[string]string, len(i.aliases))
	maps.Copy(aliases, i.aliases)

	return aliases
}

// serve executes a matching native hook and reports whether the request was handled.
func (i *nativeHookIndex) serve(
	ctx *gin.Context,
	cfg config.File,
	logger *slog.Logger,
	validator oidcbearer.TokenValidator,
	location string,
	method string,
) bool {
	hook, found := i.lookup(location, method)
	if !found {
		return false
	}

	traceCtx, span := startNativeHookSpan(ctx, hook)
	requestScope := util.NewHTTPRequestContextScope(traceCtx, &ctx.Request)

	defer requestScope.Restore()
	defer span.End()

	if !authorizeNativeHook(ctx, cfg, validator, hook.Descriptor) {
		span.SetAttributes(attribute.Int("http.status_code", ctx.Writer.Status()))

		return true
	}

	body, ok := readNativeHookBody(ctx, hook.Descriptor.MaxBodyBytes)
	if !ok {
		span.SetAttributes(attribute.Int("http.status_code", ctx.Writer.Status()))

		return true
	}

	request, err := hook.BuildRequest(ctx, cfg, hook.Descriptor, nativeHookCaller(ctx), body)
	if err != nil {
		recordNativeHookFailure(ctx, logger, hook, span, "native plugin hook request build failed", http.StatusInternalServerError)

		return true
	}

	callCtx, cancel := nativeHookCallContext(ctx.Request.Context(), hook.Descriptor.Timeout)
	defer cancel()

	response, err := hook.Runner.ServeHook(callCtx, hook.QualifiedName, request)
	if err != nil {
		status := nativeHookErrorStatus(err)
		recordNativeHookFailure(ctx, logger, hook, span, "native plugin hook failed", status)

		return true
	}

	if err := writeNativeHookResponse(ctx, cfg, response); err != nil {
		recordNativeHookFailure(ctx, logger, hook, span, "native plugin hook response rejected", http.StatusBadGateway)

		return true
	}

	span.SetAttributes(attribute.Int("http.status_code", nativeHookStatusCode(response.StatusCode)))

	return true
}

// lookup returns a native hook by normalized method and location.
func (i *nativeHookIndex) lookup(location string, method string) (NativeHook, bool) {
	if i == nil || len(i.hooks) == 0 {
		return NativeHook{}, false
	}

	hook, found := i.hooks[nativeHookKey(location, method)]

	return hook, found
}

// startNativeHookSpan starts a host-owned span for native hook execution.
func startNativeHookSpan(ctx *gin.Context, hook NativeHook) (context.Context, oteltrace.Span) {
	requestCtx := context.Background()
	if ctx != nil && ctx.Request != nil {
		requestCtx = ctx.Request.Context()
	}

	tracer := monittrace.New("nauthilus/plugin/hooks")
	nextCtx, span := tracer.Start(requestCtx, "plugin.hook.serve",
		attribute.String("plugin.module", hook.ModuleName),
		attribute.String("plugin.component", hook.ComponentName),
		attribute.String("plugin.hook", hook.QualifiedName),
	)

	return nextCtx, span
}

// authorizeNativeHook enforces descriptor auth and scope before plugin invocation.
func authorizeNativeHook(
	ctx *gin.Context,
	cfg config.File,
	validator oidcbearer.TokenValidator,
	descriptor pluginapi.HookDescriptor,
) bool {
	requiredScopes := nativeHookRequiredScopes(descriptor.Scope)

	switch descriptor.Auth {
	case pluginapi.HookAuthNone:
		if len(requiredScopes) > 0 {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{nativeHookErrorField: "hook scope requires authentication"})

			return false
		}

		return true
	case pluginapi.HookAuthToken:
		return enforceNativeHookToken(ctx, cfg, validator, requiredScopes)
	case pluginapi.HookAuthAdmin:
		return enforceNativeHookAdmin(ctx, cfg, validator)
	case pluginapi.HookAuthSession:
		if ctx.GetBool(definitions.CtxBasicAuthValidatedKey) {
			return true
		}

		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{nativeHookErrorField: "session authentication required"})

		return false
	default:
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return false
	}
}

// enforceNativeHookToken validates bearer auth and required hook scopes.
func enforceNativeHookToken(
	ctx *gin.Context,
	cfg config.File,
	validator oidcbearer.TokenValidator,
	requiredScopes []string,
) bool {
	if validator == nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{nativeHookErrorField: "authentication required but not configured"})

		return false
	}

	_, ok := oidcbearer.EnforceBearerScopeAuth(ctx, validator, cfg, oidcbearer.EnforceBearerScopeAuthOptions{
		RequiredScopes:         requiredScopes,
		MissingScopeMessage:    "insufficient permissions",
		ThrottleOnMissingToken: false,
	})

	return ok
}

// enforceNativeHookAdmin requires administrative bearer authority for admin hooks.
func enforceNativeHookAdmin(ctx *gin.Context, cfg config.File, validator oidcbearer.TokenValidator) bool {
	return enforceNativeHookToken(ctx, cfg, validator, []string{definitions.ScopeAdmin})
}

// nativeHookRequiredScopes maps public hook scope to Nauthilus control-plane scopes.
func nativeHookRequiredScopes(scope pluginapi.HookScope) []string {
	switch scope {
	case pluginapi.HookScopePublic:
		return nil
	case pluginapi.HookScopeInternal:
		return []string{definitions.ScopeAuthenticate}
	case pluginapi.HookScopeAdmin:
		return []string{definitions.ScopeAdmin}
	default:
		return []string{definitions.ScopeAdmin}
	}
}

// readNativeHookBody enforces the bounded v1 hook body model.
func readNativeHookBody(ctx *gin.Context, limit int64) ([]byte, bool) {
	limit = effectiveNativeHookBodyLimit(limit)
	if limit < 0 {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return nil, false
	}

	if ctx.Request == nil || ctx.Request.Body == nil || ctx.Request.Body == http.NoBody {
		return nil, true
	}

	if ctx.Request.ContentLength > limit {
		ctx.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{nativeHookErrorField: nativeHookBodyTooLarge})

		return nil, false
	}

	body, err := util.ReadBoundedRequestBody(ctx.Request.Body, limit)
	if err != nil {
		if errors.Is(err, util.ErrRequestBodyTooLarge) {
			ctx.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{nativeHookErrorField: nativeHookBodyTooLarge})

			return nil, false
		}

		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{nativeHookErrorField: "invalid hook request body"})

		return nil, false
	}

	return body, true
}

// effectiveNativeHookBodyLimit applies the global default when a hook omits a limit.
func effectiveNativeHookBodyLimit(limit int64) int64 {
	if limit == 0 {
		return util.DefaultHTTPRequestBodyLimit
	}

	return limit
}

// nativeHookCallContext applies a hook-specific timeout when configured.
func nativeHookCallContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, timeout)
}

// nativeHookErrorStatus maps runtime failures to secret-safe HTTP status codes.
func nativeHookErrorStatus(err error) int {
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}

	return http.StatusInternalServerError
}

// recordNativeHookFailure writes a secret-safe log entry and HTTP error.
func recordNativeHookFailure(
	ctx *gin.Context,
	logger *slog.Logger,
	hook NativeHook,
	span oteltrace.Span,
	message string,
	status int,
) {
	if logger == nil {
		logger = slog.Default()
	}

	if span != nil {
		span.RecordError(fmt.Errorf("%s", message))
		span.SetAttributes(attribute.Int("http.status_code", status))
	}

	_ = level.Error(logger).Log(
		definitions.LogKeyMsg, message,
		"module", hook.ModuleName,
		"component", hook.ComponentName,
		"hook", hook.QualifiedName,
	)

	switch status {
	case http.StatusGatewayTimeout:
		ctx.AbortWithStatusJSON(status, gin.H{nativeHookErrorField: "plugin hook timeout"})
	case http.StatusBadGateway:
		ctx.AbortWithStatusJSON(status, gin.H{nativeHookErrorField: "plugin hook response rejected"})
	default:
		ctx.AbortWithStatusJSON(status, gin.H{nativeHookErrorField: "plugin hook failed"})
	}
}

// writeNativeHookResponse filters headers and writes the plugin response.
func writeNativeHookResponse(ctx *gin.Context, cfg config.File, response pluginapi.HookResponse) error {
	headers, err := safeNativeHookResponseHeaders(response.Headers, cfg)
	if err != nil {
		return err
	}

	statusCode := nativeHookStatusCode(response.StatusCode)
	if statusCode == http.StatusBadGateway && response.StatusCode != 0 {
		return fmt.Errorf("invalid hook response status code %d", response.StatusCode)
	}

	for key, values := range headers {
		for _, value := range values {
			ctx.Writer.Header().Add(key, value)
		}
	}

	ctx.Status(statusCode)

	if !nativeHookCanWriteBody(ctx, response.Body) {
		return nil
	}

	_, err = ctx.Writer.Write(response.Body)

	return err
}

// nativeHookCanWriteBody keeps HEAD responses header-only at the host boundary.
func nativeHookCanWriteBody(ctx *gin.Context, body []byte) bool {
	if len(body) == 0 {
		return false
	}

	if ctx != nil && ctx.Request != nil && ctx.Request.Method == http.MethodHead {
		return false
	}

	return true
}

// safeNativeHookResponseHeaders rejects unsafe plugin-controlled response headers.
func safeNativeHookResponseHeaders(headers map[string][]string, cfg config.File) (http.Header, error) {
	if len(headers) == 0 {
		return http.Header{}, nil
	}

	secretHeaders := nativeHookResponseSecretHeaders(cfg)

	output := make(http.Header, len(headers))
	for key, values := range headers {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(key))
		if canonical == "" || !httpguts.ValidHeaderFieldName(canonical) {
			return nil, fmt.Errorf("invalid hook response header name %q", key)
		}

		if nativeHookHeaderDenied(canonical, secretHeaders) {
			return nil, fmt.Errorf("hook response header %q is host-owned", canonical)
		}

		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return nil, fmt.Errorf("invalid hook response header value for %q", canonical)
			}

			output.Add(canonical, value)
		}
	}

	return output, nil
}

// nativeHookHeaderDenied reports whether a response header is host-owned or hop-by-hop.
func nativeHookHeaderDenied(header string, secretHeaders map[string]struct{}) bool {
	if _, denied := nativeHookForbiddenResponseHeaders[header]; denied {
		return true
	}

	if _, denied := nativeHookHopByHopHeaders[header]; denied {
		return true
	}

	if _, denied := nativeHookHostOwnedHeaders[header]; denied {
		return true
	}

	_, denied := secretHeaders[header]

	return denied
}

// nativeHookResponseSecretHeaders derives configured password-bearing headers.
func nativeHookResponseSecretHeaders(cfg config.File) map[string]struct{} {
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

// nativeHookStatusCode validates and defaults plugin response status codes.
func nativeHookStatusCode(statusCode int) int {
	if statusCode == 0 {
		return http.StatusOK
	}

	if statusCode < 100 || statusCode > 599 {
		return http.StatusBadGateway
	}

	return statusCode
}

// nativeHookCaller extracts validated caller claims from Gin context.
func nativeHookCaller(ctx *gin.Context) NativeHookCaller {
	claims := oidcbearer.GetClaimsFromContext(ctx)
	subject := claimString(claims, "sub")
	clientID := firstNonEmptyClaim(claims, "client_id", "azp", "sub")

	return NativeHookCaller{
		Subject:       subject,
		ClientID:      clientID,
		Authenticated: len(claims) > 0 || ctx.GetBool(definitions.CtxBasicAuthValidatedKey),
	}
}

// firstNonEmptyClaim returns the first non-empty string claim.
func firstNonEmptyClaim(claims jwt.MapClaims, keys ...string) string {
	for _, key := range keys {
		if value := claimString(claims, key); value != "" {
			return value
		}
	}

	return ""
}

// claimString extracts one string claim value.
func claimString(claims jwt.MapClaims, key string) string {
	value, ok := claims[key].(string)
	if !ok {
		return ""
	}

	return value
}

// nativeHookKey returns the map key for one hook location and method.
func nativeHookKey(location string, method string) string {
	return normalizeNativeHookPath(location) + ":" + strings.ToUpper(strings.TrimSpace(method))
}

// normalizeNativeHookPath returns an absolute hook path without normalizing semantics.
func normalizeNativeHookPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}

	return "/" + strings.TrimLeft(trimmed, "/")
}
