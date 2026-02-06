// Copyright (C) 2024 Christian Rößner
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

// Package csrf provides Cross-Site Request Forgery (CSRF) protection middleware for Gin.
// It implements a double-submit cookie pattern with masked tokens to prevent BREACH attacks.
//
// The middleware:
//   - Generates a random 32-byte token stored in a cookie
//   - Returns a masked (64-byte) token for use in forms/headers
//   - Validates that the masked token matches the cookie token on unsafe HTTP methods
//   - Validates Origin/Referer headers for same-origin requests
package csrf

import (
	"errors"
	"net/http"
	"net/url"
	"slices"

	"github.com/gin-gonic/gin"
)

const (
	// CookieName is the default name of the CSRF cookie.
	CookieName = "csrf_token"

	// FormFieldName is the default name of the CSRF form field.
	FormFieldName = "csrf_token"

	// HeaderName is the default name of the CSRF header.
	HeaderName = "X-CSRF-Token"

	// FailureCode is the HTTP status code returned on CSRF failure.
	FailureCode = http.StatusBadRequest

	// MaxAge is the default max-age for the CSRF cookie (365 days in seconds).
	MaxAge = 365 * 24 * 60 * 60

	// csrfContextKey is the key used to store CSRF context in Gin context.
	csrfContextKey = "csrf_context"
)

// safeMethods are HTTP methods that don't require CSRF validation.
var safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}

// csrfContext holds CSRF-related data in the request context.
type csrfContext struct {
	token  string // The masked, base64-encoded token for forms/headers
	reason error  // The reason for CSRF failure, if any
}

// Handler defines the interface for CSRF protection handlers.
type Handler interface {
	// Middleware returns a Gin middleware handler.
	Middleware() gin.HandlerFunc
	// Token returns the current CSRF token for the request.
	Token(ctx *gin.Context) string
	// RegenerateToken generates a new token and returns the masked token string.
	RegenerateToken(ctx *gin.Context) string
	// SetFailureHandler sets a custom handler for CSRF failures.
	SetFailureHandler(handler gin.HandlerFunc)
	// SetBaseCookie sets the base cookie used for CSRF tokens.
	SetBaseCookie(cookie http.Cookie)
}

// OriginValidator defines the interface for validating request origins.
type OriginValidator interface {
	// ValidateOrigin checks if the request comes from a valid origin.
	ValidateOrigin(r *http.Request, selfOrigin *url.URL) error
}

// DefaultHandler implements the Handler interface for CSRF protection.
type DefaultHandler struct {
	failureHandler  gin.HandlerFunc
	baseCookie      http.Cookie
	generator       TokenGenerator
	masker          TokenMasker
	validator       TokenValidator
	encoder         TokenEncoder
	originValidator OriginValidator
}

// Option is a function that configures a DefaultHandler.
type Option func(*DefaultHandler)

// NewHandler creates a new CSRF handler with the given options.
func NewHandler(opts ...Option) *DefaultHandler {
	h := &DefaultHandler{
		failureHandler: defaultFailureHandler,
		baseCookie: http.Cookie{
			MaxAge:   MaxAge,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   true,
			Path:     "/",
		},
		generator:       NewTokenGenerator(),
		masker:          NewTokenMasker(),
		validator:       NewTokenValidator(),
		encoder:         NewTokenEncoder(),
		originValidator: NewOriginValidator(),
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// WithFailureHandler sets a custom failure handler.
func WithFailureHandler(handler gin.HandlerFunc) Option {
	return func(h *DefaultHandler) {
		h.failureHandler = handler
	}
}

// WithBaseCookie sets the base cookie configuration.
func WithBaseCookie(cookie http.Cookie) Option {
	return func(h *DefaultHandler) {
		h.baseCookie = cookie
	}
}

// WithGenerator sets a custom token generator.
func WithGenerator(generator TokenGenerator) Option {
	return func(h *DefaultHandler) {
		h.generator = generator
	}
}

// WithMasker sets a custom token masker.
func WithMasker(masker TokenMasker) Option {
	return func(h *DefaultHandler) {
		h.masker = masker
	}
}

// WithValidator sets a custom token validator.
func WithValidator(validator TokenValidator) Option {
	return func(h *DefaultHandler) {
		h.validator = validator
	}
}

// WithEncoder sets a custom token encoder.
func WithEncoder(encoder TokenEncoder) Option {
	return func(h *DefaultHandler) {
		h.encoder = encoder
	}
}

// WithOriginValidator sets a custom origin validator.
func WithOriginValidator(validator OriginValidator) Option {
	return func(h *DefaultHandler) {
		h.originValidator = validator
	}
}

// defaultFailureHandler returns a 400 Bad Request on CSRF failure.
func defaultFailureHandler(ctx *gin.Context) {
	ctx.String(FailureCode, http.StatusText(FailureCode))
	ctx.Abort()
}

// Middleware returns the Gin middleware handler for CSRF protection.
func (h *DefaultHandler) Middleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Initialize CSRF context
		csrfCtx := &csrfContext{}
		ctx.Set(csrfContextKey, csrfCtx)

		// Add Vary header to prevent caching issues
		ctx.Writer.Header().Add("Vary", "Cookie")

		// Get or generate the real token from cookie
		realToken := h.getRealToken(ctx)

		if len(realToken) != tokenLength {
			// Token is invalid or missing, regenerate
			realToken = h.regenerateToken(ctx)
		}

		// Store the masked token in context
		h.setContextToken(ctx, realToken)

		// Safe methods don't need CSRF validation
		if slices.Contains(safeMethods, ctx.Request.Method) {
			ctx.Next()

			return
		}

		// Validate origin/referer
		if err := h.validateSameOrigin(ctx); err != nil {
			csrfCtx.reason = err
			h.failureHandler(ctx)

			return
		}

		// Extract and validate the sent token
		sentToken := h.extractToken(ctx)

		if !h.validator.Validate(realToken, sentToken) {
			csrfCtx.reason = ErrBadToken
			h.failureHandler(ctx)

			return
		}

		ctx.Next()
	}
}

// Token returns the current CSRF token for the request.
// Returns an empty string if no token is available.
func (h *DefaultHandler) Token(ctx *gin.Context) string {
	csrfCtx, ok := ctx.Get(csrfContextKey)
	if !ok {
		return ""
	}

	if c, ok := csrfCtx.(*csrfContext); ok {
		return c.token
	}

	return ""
}

// RegenerateToken generates a new token and returns the masked token string.
func (h *DefaultHandler) RegenerateToken(ctx *gin.Context) string {
	h.regenerateToken(ctx)

	return h.Token(ctx)
}

// SetFailureHandler sets a custom handler for CSRF failures.
func (h *DefaultHandler) SetFailureHandler(handler gin.HandlerFunc) {
	h.failureHandler = handler
}

// SetBaseCookie sets the base cookie used for CSRF tokens.
func (h *DefaultHandler) SetBaseCookie(cookie http.Cookie) {
	h.baseCookie = cookie
}

// Reason returns the reason for CSRF failure, if any.
func (h *DefaultHandler) Reason(ctx *gin.Context) error {
	csrfCtx, ok := ctx.Get(csrfContextKey)
	if !ok {
		return nil
	}

	if c, ok := csrfCtx.(*csrfContext); ok {
		return c.reason
	}

	return nil
}

// getRealToken extracts the real (unmasked) token from the cookie.
func (h *DefaultHandler) getRealToken(ctx *gin.Context) []byte {
	cookieName := h.getCookieName()

	tokenCookie, err := ctx.Cookie(cookieName)
	if err != nil {
		return nil
	}

	decoded, err := h.encoder.Decode(tokenCookie)
	if err != nil {
		return nil
	}

	return decoded
}

// regenerateToken generates a new token, sets it in the cookie, and returns it.
func (h *DefaultHandler) regenerateToken(ctx *gin.Context) []byte {
	token, err := h.generator.Generate()
	if err != nil {
		return nil
	}

	h.setTokenCookie(ctx, token)
	h.setContextToken(ctx, token)

	return token
}

// setTokenCookie sets the CSRF token cookie.
func (h *DefaultHandler) setTokenCookie(ctx *gin.Context, token []byte) {
	cookie := h.baseCookie
	cookie.Name = h.getCookieName()
	cookie.Value = h.encoder.Encode(token)

	http.SetCookie(ctx.Writer, &cookie)
}

// setContextToken stores the masked token in the request context.
func (h *DefaultHandler) setContextToken(ctx *gin.Context, token []byte) {
	csrfCtx, ok := ctx.Get(csrfContextKey)
	if !ok {
		return
	}

	c, ok := csrfCtx.(*csrfContext)
	if !ok {
		return
	}

	masked, err := h.masker.Mask(token)
	if err != nil {
		return
	}

	c.token = h.encoder.Encode(masked)
}

// extractToken extracts the sent token from the request (header or form).
func (h *DefaultHandler) extractToken(ctx *gin.Context) []byte {
	// Try header first
	sentToken := ctx.GetHeader(HeaderName)

	// Then try POST form value
	if sentToken == "" {
		sentToken = ctx.PostForm(FormFieldName)
	}

	// Try multipart form
	if sentToken == "" && ctx.Request.MultipartForm != nil {
		if vals, ok := ctx.Request.MultipartForm.Value[FormFieldName]; ok && len(vals) > 0 {
			sentToken = vals[0]
		}
	}

	if sentToken == "" {
		return nil
	}

	decoded, err := h.encoder.Decode(sentToken)
	if err != nil {
		return nil
	}

	return decoded
}

// getCookieName returns the cookie name, using the base cookie name if set.
func (h *DefaultHandler) getCookieName() string {
	if h.baseCookie.Name != "" {
		return h.baseCookie.Name
	}

	return CookieName
}

// validateSameOrigin validates that the request comes from the same origin.
func (h *DefaultHandler) validateSameOrigin(ctx *gin.Context) error {
	selfOrigin := &url.URL{
		Scheme: "http",
		Host:   ctx.Request.Host,
	}

	// Assume HTTPS for most production scenarios
	if ctx.Request.TLS != nil || ctx.GetHeader("X-Forwarded-Proto") == "https" {
		selfOrigin.Scheme = "https"
	}

	// Check Sec-Fetch-Site header first (modern browsers)
	if ctx.GetHeader("Sec-Fetch-Site") == "same-origin" {
		return nil
	}

	return h.originValidator.ValidateOrigin(ctx.Request, selfOrigin)
}

// DefaultOriginValidator implements OriginValidator.
type DefaultOriginValidator struct {
	allowedOrigins []*url.URL
}

// NewOriginValidator creates a new DefaultOriginValidator.
func NewOriginValidator(allowedOrigins ...string) *DefaultOriginValidator {
	v := &DefaultOriginValidator{}

	for _, origin := range allowedOrigins {
		if u, err := url.Parse(origin); err == nil {
			v.allowedOrigins = append(v.allowedOrigins, u)
		}
	}

	return v
}

// ValidateOrigin validates that the request comes from an allowed origin.
func (v *DefaultOriginValidator) ValidateOrigin(r *http.Request, selfOrigin *url.URL) error {
	// Try Origin header first
	if err := v.checkOrigin(r, selfOrigin); err == nil {
		return nil
	} else if !errors.Is(err, errNoOrigin) {
		return err
	}

	// Fall back to Referer header
	return v.checkReferer(r, selfOrigin)
}

// checkOrigin validates the Origin header.
func (v *DefaultOriginValidator) checkOrigin(r *http.Request, selfOrigin *url.URL) error {
	originStr := r.Header.Get("Origin")
	if originStr == "" || originStr == "null" {
		return errNoOrigin
	}

	origin, err := url.Parse(originStr)
	if err != nil {
		return err
	}

	if sameOrigin(selfOrigin, origin) {
		return nil
	}

	for _, allowed := range v.allowedOrigins {
		if sameOrigin(allowed, origin) {
			return nil
		}
	}

	return ErrBadOrigin
}

// checkReferer validates the Referer header.
func (v *DefaultOriginValidator) checkReferer(r *http.Request, selfOrigin *url.URL) error {
	referer, err := url.Parse(r.Referer())
	if err != nil || referer.String() == "" {
		return ErrNoReferer
	}

	if sameOrigin(selfOrigin, referer) {
		return nil
	}

	for _, allowed := range v.allowedOrigins {
		if sameOrigin(allowed, referer) {
			return nil
		}
	}

	return ErrBadReferer
}

// sameOrigin checks if two URLs have the same origin (scheme and host).
func sameOrigin(u1, u2 *url.URL) bool {
	return u1.Scheme == u2.Scheme && u1.Host == u2.Host
}

// New creates a new CSRF middleware with default settings.
// This is a convenience function for simple usage.
func New() gin.HandlerFunc {
	return NewHandler().Middleware()
}

// Global handler instance for Token function.
var globalHandler = NewHandler()

// Token returns the CSRF token for the given Gin context.
// This function requires that the CSRF middleware has been applied to the route.
func Token(ctx *gin.Context) string {
	return globalHandler.Token(ctx)
}

// GetToken returns the CSRF token for the given Gin context.
// This is an alias for Token for compatibility.
func GetToken(ctx *gin.Context) string {
	return Token(ctx)
}
